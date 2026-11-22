# Security Review: Headroom LLM Proxy (auth / SSRF / unauth surfaces)

Date: 2026-11-22  
Scope: `headroom/proxy/*`, `headroom/providers/proxy_routes.py`, `headroom/copilot_auth.py`, `crates/headroom-proxy/*`  
Method: source-traced attacker input → sink only; speculative issues omitted.

## Summary

Five validated high-impact findings. The dominant chain is **unauthenticated client control of upstream base URL** (`X-Headroom-Base-Url`) on the catch-all passthrough, which yields SSRF and can trigger **host Copilot credential injection**. Container/Rust defaults that bind `0.0.0.0` make this remotely reachable without localhost.

`auth_mode.py` / `classify_auth_mode` are **not** access control — they only classify compression policy. `forwarded_headers.py` correctly ignores untrusted `X-Forwarded-*` by default. Loopback debug guards use `request.client.host` (not XFF), so XFF does not bypass `/debug/*`.

---

## Finding 1 — Critical

**Title:** Unauthenticated SSRF via `X-Headroom-Base-Url` on catch-all passthrough  
**Location:** `headroom/providers/proxy_routes.py`

### Description

The catch-all route honors an attacker-supplied `X-Headroom-Base-Url` with **no authentication, no URL allowlist, and no scheme/host validation**. That value becomes the upstream base for `handle_passthrough`, which issues an HTTP request with the client’s remaining headers (including `Authorization` / `api-key` / `x-api-key`) after only stripping `x-headroom-*`.

### Impact

- Server-side request forgery to arbitrary hosts (cloud metadata, RFC1918, localhost services).
- Credential exfiltration when the client (or a browser-abused local proxy) also sends vendor API keys — those keys are forwarded to the attacker-chosen URL.
- Combined with Finding 2: host Copilot tokens can be attached automatically.

### Attack path

1. Reach the proxy (local default `127.0.0.1`, or remote if bound/`0.0.0.0` as in Docker/Rust defaults).
2. Send any method to a path **not** claimed by a more specific route, e.g. `GET /latest/meta-data/`.
3. Set header `X-Headroom-Base-Url: http://169.254.169.254` (or `http://attacker.example`).
4. Proxy builds `url = base + path` and calls `http_client.request(...)`.
5. Response body/status is returned to the attacker.

### Evidence

```869:873:headroom/providers/proxy_routes.py
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def passthrough(request: Request, path: str):
        custom_base = request.headers.get("x-headroom-base-url")
        if custom_base:
            return await proxy.handle_passthrough(request, custom_base.rstrip("/"))
```

```6048:6088:headroom/proxy/handlers/openai.py
        url = build_copilot_upstream_url(base_url, path)
        ...
        headers = dict(request.headers.items())
        headers.pop("host", None)
        ...
        headers = _strip_internal_headers(headers)
        ...
        headers = await apply_copilot_api_auth(headers, url=url)
        ...
            response = await passthrough_client.request(  # type: ignore[union-attr]
                method=request.method,
                url=url,
                headers=headers,
                content=body,
            )
```

Secondary path (Azure-style) also accepts the same header when `api-key` is present:

```65:68:headroom/providers/proxy_routes.py
    if headers.get("api-key"):
        azure_base = headers.get("x-headroom-base-url", "")
        if azure_base:
            return azure_base.rstrip("/")
```

### Why existing controls fail

- Loopback guards apply only to `/debug/*` and a few admin routes — not the catch-all.
- `_strip_internal_headers` removes the control header from the **outbound** request but does not stop using it to choose the destination.
- No SSRF allowlist / private-IP block / scheme restriction exists on this path.
- Proxy has no request authentication layer for passthrough.

### Remediation

- Remove client-controlled upstream override from unauthenticated catch-all, **or** gate it behind strong proxy auth plus an explicit allowlist of hosts/CIDRs.
- Reject non-HTTPS (except explicit operator-configured targets), block link-local/RFC1918/metadata ranges, and pin DNS.
- Never forward caller secrets to a caller-chosen host; require the override URL to match operator config.

---

## Finding 2 — Critical

**Title:** Host Copilot OAuth/API token injected onto attacker-chosen Copilot upstream  
**Location:** `headroom/copilot_auth.py`

### Description

After the SSRF base URL is applied, `apply_copilot_api_auth` runs on the constructed URL. If the URL host looks like GitHub Copilot API, and the request lacks a suitable `tid_*` bearer token, the proxy loads the **host’s** Copilot OAuth/API token (env / cached auth file / OS keychain) and sets `Authorization: Bearer <host token>`.

An unauthenticated caller can therefore spend or abuse the machine’s Copilot subscription without supplying any secret.

### Impact

Unauthorized use of the operator’s GitHub Copilot credentials/quota; possible account abuse via Copilot API as the victim.

### Attack path

1. Ensure the victim host has Copilot auth available to Headroom (`GITHUB_COPILOT_*`, cached oauth, etc.).
2. `GET /v1internal/anything` (or any catch-all path) with  
   `X-Headroom-Base-Url: https://api.githubcopilot.com`.
3. `is_copilot_api_url(url)` is true → `get_copilot_token_provider().get_api_token()` runs.
4. Host token is injected; Copilot response returns to the attacker.

### Evidence

```1103:1134:headroom/copilot_auth.py
async def apply_copilot_api_auth(headers: dict[str, str], *, url: str) -> dict[str, str]:
    """Apply Copilot auth headers for GitHub Copilot API requests."""
    resolved = dict(headers)
    if not is_copilot_api_url(url):
        return resolved
    ...
    token = await get_copilot_token_provider().get_api_token()
    for key in list(resolved):
        if key.lower() in {"authorization", "x-api-key"}:
            resolved.pop(key)
    resolved["Authorization"] = f"Bearer {token.token}"
    return resolved
```

```896:908:headroom/copilot_auth.py
def is_copilot_api_url(url: str | None) -> bool:
    ...
    return _is_public_copilot_api_host(hostname) or _is_ghe_copilot_api_host(hostname)
```

### Why existing controls fail

- Credential injection is keyed only on destination host shape, not on whether the destination was operator-configured vs client-overridden.
- No authentication on the HTTP surface that triggers injection.

### Remediation

- Never call `apply_copilot_api_auth` / host token provider when upstream base came from a client header.
- Restrict Copilot token injection to operator-configured `OPENAI_TARGET_API_URL` / Copilot wrap paths only.
- Require local auth (or disable host-token injection) whenever the listener is non-loopback.

---

## Finding 3 — High

**Title:** WebSocket `/v1/responses` injects `OPENAI_API_KEY` when client sends no Authorization  
**Location:** `headroom/proxy/handlers/openai.py`

### Description

On the Responses WebSocket path, if the upgrade request has no `Authorization` header, the proxy silently injects `Bearer ${OPENAI_API_KEY}` from the process environment, then continues to Copilot auth application.

### Impact

Any client that can open `ws://<proxy>/v1/responses` can spend the host’s OpenAI API key (and/or trigger Copilot injection when upstream is Copilot).

### Attack path

1. Proxy process has `OPENAI_API_KEY` set.
2. Attacker opens WebSocket to `/v1/responses` with no auth header.
3. Proxy injects the env key and connects upstream.
4. Attacker sends billing-generating Responses traffic.

### Evidence

```3645:3658:headroom/proxy/handlers/openai.py
        # Ensure Authorization header is present — fall back to OPENAI_API_KEY env var.
        # Safety net for clients that don't forward auth headers via WebSocket upgrade.
        if "authorization" not in _lower_headers:
            api_key = os.environ.get("OPENAI_API_KEY")
            if api_key:
                upstream_headers["Authorization"] = f"Bearer {api_key}"
                logger.debug(f"[{request_id}] WS: injected Authorization from OPENAI_API_KEY env")
            else:
                logger.warning(
                    f"[{request_id}] WS: no Authorization header from client and "
                    f"OPENAI_API_KEY not set — upstream will likely reject"
                )

        upstream_headers = await apply_copilot_api_auth(upstream_headers, url=upstream_url)
```

### Why existing controls fail

- Intended “safety net” for local CLIs becomes an unauthenticated spending oracle whenever the listener is reachable.
- No shared-secret / loopback restriction on the WS route.

### Remediation

- Remove env-key auto-injection on unauthenticated requests, or require an explicit opt-in **and** loopback-only / proxy-auth.
- Fail closed (close WS with 1008/401) when the client omits Authorization.

---

## Finding 4 — High

**Title:** Default non-loopback bind + open CORS turns local proxy bugs into remote/browser-reachable ones  
**Location:** `headroom/proxy/server.py` (CORS); `Dockerfile` / `docker-compose.yml`; `crates/headroom-proxy/src/config.rs`

### Description

Python CLI defaults to `127.0.0.1`, but Docker images and compose force `0.0.0.0`, and the Rust proxy defaults to `0.0.0.0:8787`. The Python app also installs `CORSMiddleware` with `allow_origins=["*"]`, `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]`.

Together with Findings 1–3, any published port is an unauthenticated open LLM/SSRF proxy. Wide CORS maximizes browser ability to invoke custom headers (including `X-Headroom-Base-Url`) against a reachable origin.

### Impact

Remote LAN/internet exploitation of SSRF and credential injection; easier cross-origin browser abuse against exposed proxies.

### Attack path

1. Deploy via Docker (`CMD --host 0.0.0.0`) or Rust default listen, publish `8787`.
2. From another host (or browser JS to that origin), exercise Finding 1/2/3.
3. No proxy password or mTLS is required.

### Evidence

```2133:2140:headroom/proxy/server.py
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

```102:112:Dockerfile
ENV HEADROOM_HOST=0.0.0.0 \
    ...
CMD ["--host", "0.0.0.0", "--port", "8787"]
```

```1:11:docker-compose.yml
  headroom-proxy:
    ...
    command: ["--host", "0.0.0.0"]
    environment:
      - HEADROOM_HOST=0.0.0.0
    ports:
      - "8787:8787"
```

```191:193:crates/headroom-proxy/src/config.rs
    /// Address the proxy listens on (e.g. 0.0.0.0:8787).
    #[arg(long, env = "HEADROOM_PROXY_LISTEN", default_value = "0.0.0.0:8787")]
    pub listen: SocketAddr,
```

### Why existing controls fail

- Loopback Host-header hardening is limited to debug endpoints; LLM/passthrough routes stay open.
- Rust proxy has no equivalent of Python’s safer CLI default bind.
- CORS is intentionally maximal for local dashboards and was not threat-modeled against credential-bearing proxy routes.

### Remediation

- Default all listen addresses to loopback; require explicit opt-in for `0.0.0.0`.
- For non-loopback binds, require proxy authentication (shared secret / mTLS) before any upstream forward or host-credential injection.
- Tighten CORS to known dashboard origins; never `*` with credentials on proxy API routes.

---

## Finding 5 — High

**Title:** Unauthenticated CCR retrieve returns original compressed tool content  
**Location:** `headroom/proxy/server.py`

### Description

`GET/POST /v1/retrieve` and `GET /v1/retrieve/{hash_key}` are unauthenticated. Given a CCR hash (often embedded in compressed prompts/markers visible to agents or logs), any caller can read `original_content` from the compression store — frequently tool outputs that contain secrets, source, or PII.

Related unauthenticated mutating/sensitive surfaces on the same app (no loopback guard): `POST /cache/clear`, `POST /v1/telemetry/import`, `GET /stats`, `GET /metrics`, `GET /dashboard`.

### Impact

Confidentiality loss of cached tool payloads; cache wipe DoS; telemetry poisoning; recon via metrics/stats when the proxy is network-exposed.

### Attack path

1. Obtain or observe a CCR hash from a compressed transcript/marker.
2. `GET /v1/retrieve/<hash>` against the proxy with no auth.
3. Receive `original_content`.

### Evidence

```3454:3485:headroom/proxy/server.py
    @app.get("/v1/retrieve/{hash_key}")
    async def ccr_retrieve_get(hash_key: str, query: str | None = None):
        """GET version of CCR retrieve for easier testing."""
        store = get_compression_store()
        ...
            entry = store.retrieve(hash_key)
            if entry:
                return {
                    "hash": hash_key,
                    "original_content": entry.original_content,
                    ...
                }
```

```3103:3108:headroom/proxy/server.py
    @app.post("/cache/clear")
    async def clear_cache():
        """Clear the response cache."""
        if proxy.cache:
            await proxy.cache.clear()
```

```3304:3316:headroom/proxy/server.py
    @app.post("/v1/telemetry/import")
    async def telemetry_import(request: Request):
        ...
        telemetry.import_stats(data)
        return {"status": "imported", "current_stats": telemetry.get_stats()}
```

### Why existing controls fail

- CCR retrieve is designed for LLM tool callbacks and was left open like the LLM API surface.
- Only a subset of admin/debug routes use `require_loopback`.

### Remediation

- Bind retrieve/cache/telemetry-import to loopback **or** require the same proxy auth as upstream routes.
- Prefer short-lived retrieve tokens bound to the session that created the hash.
- Keep `/metrics`/`/stats` scrape endpoints on a separate authenticated listener.

---

## Explicit non-findings (checked, not exploitable as claimed)

| Topic | Result |
| --- | --- |
| `X-Forwarded-For` bypass of `/debug/*` | **Not vulnerable** — `require_loopback` uses `request.client.host` + Host allowlist; `resolve_client_ip` is separate and defaults to ignoring XFF. |
| Rust `x-headroom-base-url` SSRF | **Not present** — Rust forwards only to operator `--upstream`. |
| `auth_mode.py` auth bypass | N/A — classifier only; not an access-control gate. |
| Host-header SSRF on Python provider URLs | Fixed targets / operator config for OpenAI/Anthropic/Gemini/Bedrock primary handlers; Vertex location only rewrites `*-aiplatform.googleapis.com`. |

---

## Suggested fix priority

1. Disable or allowlist `X-Headroom-Base-Url` immediately (Findings 1–2).
2. Stop host credential / `OPENAI_API_KEY` injection on unauthenticated requests (Findings 2–3).
3. Fail closed on non-loopback listen without proxy auth; fix Docker/Rust defaults + CORS (Finding 4).
4. Lock down CCR retrieve and other unauthenticated mutating/data endpoints (Finding 5).
