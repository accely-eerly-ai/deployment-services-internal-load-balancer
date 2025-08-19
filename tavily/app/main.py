from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.responses import PlainTextResponse
from typing import List, Tuple
from urllib.parse import urlparse

import httpx
import asyncio
import json
import logging
import os
import time
import uuid

from app.middleware.logging_middleware import logger, request_id_ctx_var
from app.utils.application import _choose_final_status_and_headers

CONFIG_PATH = os.getenv("TAVILY_PROXY_CONFIG", "tavily_instances.json")

"""
Example config file (tavily_instances.json)

{
  "instances": [
    { "endpoint": "https://api.tavily.com", "api_key": "tvly-dev-XXXX" }
  ],
  "header_name": "authorization",        // upstream auth header
  "client_header_name": "authorization", // header to read from inbound client
  "client_keys": ["my-key-1","my-key-2"] // optional allowlist of client keys
}
"""

# ---------- Load credentials + client auth from JSON ----------
def _load_config(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Bad JSON in {path}: {e}")

    instances = data.get("instances") or []
    header_name = (data.get("header_name") or "authorization").strip()

    if not isinstance(instances, list) or not instances:
        raise RuntimeError("Config must contain a non-empty 'instances' array.")

    creds: List[Tuple[str, str]] = []
    seen = set()
    for i, item in enumerate(instances):
        ep = (item.get("endpoint") or "").strip().rstrip("/")
        key = (item.get("api_key") or "").strip()
        if not ep or not key:
            raise RuntimeError(f"instances[{i}] must include 'endpoint' and 'api_key'.")
        pair = (ep, key)
        if pair not in seen:
            creds.append(pair)
            seen.add(pair)

    client_header_name = (data.get("client_header_name") or "api-key").strip().lower()
    client_keys_cfg = data.get("client_keys") or []
    if not isinstance(client_keys_cfg, list):
        raise RuntimeError("'client_keys' must be a list when provided.")

    # Allow env var to supply/augment keys (comma-separated)
    env_keys = [s.strip() for s in os.getenv("TAVILY_PROXY_CLIENT_KEYS", "").split(",") if s.strip()]
    client_keys = set(client_keys_cfg) | set(env_keys)

    return creds, header_name, client_header_name, client_keys

CREDENTIALS, HEADER_NAME, CLIENT_HEADER_NAME, CLIENT_KEYS = _load_config(CONFIG_PATH)
N = len(CREDENTIALS)
logger.info("Loaded %d Tavily instance(s); upstream auth='%s'; inbound header='%s'; %d client key(s)",
            N, HEADER_NAME, CLIENT_HEADER_NAME, len(CLIENT_KEYS))

# ---------- Proxy + auth config ----------
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade"
}

RETRY_STATUS = {429, 500, 502, 503, 504}
RETRY_4XX = {401, 403, 404}

ERROR_BODY_MAX_BYTES = int(os.getenv("ERROR_BODY_MAX_BYTES", "2048"))
ERROR_HEADER_SNAPSHOT = ["content-type"]

MAX_BAD_KEYS = int(os.getenv("MAX_BAD_KEYS", "5"))
BLOCK_SECONDS = int(os.getenv("BLOCK_SECONDS", "300"))  # 5 minutes

app = FastAPI()
app.state.rr_pos = 0
app.state.rr_lock = asyncio.Lock()

# Track consecutive bad keys + temporary blocks (in-memory).
app.state.auth_lock = asyncio.Lock()
app.state.bad_key_counts = {}
app.state.blocked_until = {}

def _host(url: str) -> str:
    return urlparse(url).netloc or url

async def _is_blocked(ip: str) -> bool:
    now = time.time()
    until = app.state.blocked_until.get(ip)
    if until and now < until:
        return True
    if until and now >= until:
        app.state.blocked_until.pop(ip, None)
        app.state.bad_key_counts.pop(ip, None)
    return False

def _unauthorized(req_id: str, msg: str = "Invalid API key"):
    return JSONResponse(
        status_code=401,
        content={"error": "invalid_api_key", "detail": msg, "request_id": req_id},
        headers={"x-request-id": req_id},
    )

def _blocked(req_id: str, retry_after: int):
    return JSONResponse(
        status_code=403,
        content={"error": "ip_blocked", "detail": f"Too many invalid API keys. Blocked for {retry_after} seconds.", "request_id": req_id},
        headers={"x-request-id": req_id, "retry-after": str(retry_after)},
    )

@app.middleware("http")
async def proxy_middleware(request: Request, call_next):
    # Debug log: all inbound headers
    logger.info("Base headers: %s", dict(request.headers))

    req_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:8]
    request_id_ctx_var.set(req_id)

    started = time.perf_counter()
    client_ip = request.client.host if request.client else "-"

    # ---------- Inbound IP block check ----------
    async with app.state.auth_lock:
        if await _is_blocked(client_ip):
            remaining = int(app.state.blocked_until[client_ip] - time.time())
            remaining = max(1, remaining)
            logger.warning("Blocked request from %s (remaining=%ss)", client_ip, remaining)
            return _blocked(req_id, remaining)

    # ---------- Inbound API key auth ----------
    provided_auth = None
    for k, v in request.headers.items():
        if k.lower() == CLIENT_HEADER_NAME:
            provided_auth = v
            break

    provided_key = None
    if provided_auth and provided_auth.lower().startswith("bearer "):
        provided_key = provided_auth.split(" ", 1)[1].strip()

    key_ok = (provided_key is not None) and ((len(CLIENT_KEYS) == 0) or (provided_key in CLIENT_KEYS))

    if not key_ok:
        async with app.state.auth_lock:
            cnt = app.state.bad_key_counts.get(client_ip, 0) + 1
            app.state.bad_key_counts[client_ip] = cnt

            if cnt >= MAX_BAD_KEYS:
                app.state.blocked_until[client_ip] = time.time() + BLOCK_SECONDS
                app.state.bad_key_counts[client_ip] = 0
                logger.warning("IP %s blocked for %ss after %d consecutive bad keys", client_ip, BLOCK_SECONDS, MAX_BAD_KEYS)
                return _blocked(req_id, BLOCK_SECONDS)

        logger.warning("Unauthorized request from %s (bad_key_count=%d)", client_ip, app.state.bad_key_counts.get(client_ip, 0))
        return _unauthorized(req_id)

    async with app.state.auth_lock:
        if client_ip in app.state.bad_key_counts:
            app.state.bad_key_counts.pop(client_ip, None)

    # ---------- Round robin endpoint selection ----------
    async with request.app.state.rr_lock:
        start = request.app.state.rr_pos
    order_indices = [(start + off) % N for off in range(N)]
    order = [(i, CREDENTIALS[i]) for i in order_indices]

    path_and_query = request.url.path
    if request.url.query:
        path_and_query += f"?{request.url.query}"

    base_headers = {k.lower(): v for k, v in request.headers.items()
                    if k.lower() not in HOP_BY_HOP and k.lower() != "host"}
    base_headers.pop("api-key", None)
    base_headers.pop(CLIENT_HEADER_NAME, None)
    base_headers.pop("authorization", None)

    body = await request.body()
    logger.info("Request %s %s (order=%s)",
                request.method, request.url.path,
                ",".join(_host(CREDENTIALS[i][0]) for i in order_indices))

    attempts = []
    last_error = None

    timeout = httpx.Timeout(connect=10.0, read=300.0, write=300.0, pool=None)

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt_num, (abs_idx, (endpoint, api_key)) in enumerate(order, start=1):
            t0 = time.perf_counter()
            target_url = f"{endpoint}{path_and_query}"
            headers = dict(base_headers)

            if HEADER_NAME.lower() == "authorization":
                headers[HEADER_NAME] = f"Bearer {api_key}"
            else:
                headers[HEADER_NAME] = api_key

            headers.setdefault("x-request-id", req_id)

            logger.info("Attempt %d/%d -> %s", attempt_num, N, _host(endpoint))

            req = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

            try:
                upstream = await client.send(req)
            except httpx.HTTPError as e:
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                last_error = f"{type(e).__name__}: {e}"
                attempts.append({"status": None, "error": type(e).__name__, "message": str(e), "elapsed_ms": elapsed_ms})
                logger.error("Attempt %d transport error: %s", attempt_num, e)
                continue

            status = upstream.status_code
            resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP}
            resp_headers["x-request-id"] = req_id

            data = await upstream.aread()
            await upstream.aclose()

            if status in RETRY_STATUS or status in RETRY_4XX:
                ct = (resp_headers.get("content-type") or "").lower()
                truncated = len(data) > ERROR_BODY_MAX_BYTES
                preview = data[:ERROR_BODY_MAX_BYTES]

                body_json = None
                body_snippet = None
                if ("json" in ct) and not truncated:
                    try:
                        body_json = json.loads(preview.decode("utf-8", "replace"))
                    except Exception:
                        body_json = None

                if body_json is None:
                    try:
                        body_snippet = preview.decode("utf-8", "replace")
                    except Exception:
                        body_snippet = None

                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                last_error = f"HTTP {status} from {endpoint}"
                attempts.append({
                    "status": status,
                    "elapsed_ms": elapsed_ms,
                    "headers": resp_headers,
                    "content_type": ct,
                    "truncated": truncated,
                    "body_json": body_json,
                    "body_snippet": body_snippet,
                })

                level = logging.ERROR if status >= 500 else logging.WARNING
                logger.log(level, "Attempt %d got HTTP %d from %s; trying next",
                           attempt_num, status, _host(endpoint))
                continue

            if 400 <= status < 500:
                return Response(content=data, status_code=status, headers=resp_headers,
                                media_type=upstream.headers.get("content-type"))

            async with request.app.state.rr_lock:
                request.app.state.rr_pos = (abs_idx + 1) % N

            return Response(content=data, status_code=status, headers=resp_headers,
                            media_type=upstream.headers.get("content-type"))

    async with request.app.state.rr_lock:
        request.app.state.rr_pos = (start + 1) % N

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.error("All upstreams failed after %dms. Last error: %s",
                 duration_ms, last_error or "unknown error")

    status_code, extra_hdrs = _choose_final_status_and_headers(attempts)

    payload = {
        "error": "upstream_failed",
        "detail": "All upstreams failed.",
        "request_id": req_id,
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "attempts": attempts,
        "next_start_index": request.app.state.rr_pos,
        "duration_ms": duration_ms,
    }
    headers = {"x-request-id": req_id, **extra_hdrs}
    return JSONResponse(status_code=status_code, content=payload, headers=headers)

# Optional: explicit 404 for anything else (echo request id)
@app.api_route(
    "/{full_path:path}",
    methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]
)
async def catch_all(full_path: str):
    return PlainTextResponse("Not found", status_code=404, headers={"x-request-id": request_id_ctx_var.get("-")})
