from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse, PlainTextResponse
from starlette.background import BackgroundTask
from typing import List, Tuple
from urllib.parse import urlparse

import httpx
import asyncio
import json
import logging
import os
import time
import uuid
import contextvars

from app.middleware.logging_middleware import logger, request_id_ctx_var
from app.utils.application import _choose_final_status_and_headers

CONFIG_PATH = os.getenv("AZURE_PROXY_CONFIG", "azure_instances.json")

"""
Example config file (azure_instances.json)

{
  "instances": [
    { "endpoint": "https://eastus-xyz.openai.azure.com", "api_key": "XXXX" },
    { "endpoint": "https://westus-xyz.openai.azure.com", "api_key": "YYYY" },
    { "endpoint": "https://swedencentral-abc.openai.azure.com", "api_key": "ZZZZ" }
  ],
  "header_name": "api-key"
}
"""

# ---------- Load credentials from JSON ----------
def _load_config(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Bad JSON in {path}: {e}")

    instances = data.get("instances") or []
    header_name = (data.get("header_name") or "api-key").strip()

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

    return creds, header_name

CREDENTIALS, HEADER_NAME = _load_config(CONFIG_PATH)
N = len(CREDENTIALS)
logger.info("Loaded %d upstream instance(s); auth header='%s'", N, HEADER_NAME)

# ---------- Proxy config ----------
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade"
}

# Retry policy: retry true “retryables” + auth/deployment failures
RETRY_STATUS = {429, 500, 502, 503, 504}
RETRY_4XX = {401, 403, 404}

# Error payload detail controls
ERROR_BODY_MAX_BYTES = int(os.getenv("ERROR_BODY_MAX_BYTES", "2048"))
ERROR_HEADER_SNAPSHOT = ["content-type", "apim-request-id", "x-ms-request-id", "x-request-id"]

app = FastAPI()
app.state.rr_pos = 0                 # start index for next request
app.state.rr_lock = asyncio.Lock()   # protects rr_pos

def _host(url: str) -> str:
    return urlparse(url).netloc or url

@app.middleware("http")
async def proxy_middleware(request: Request, call_next):
    # set/propagate a request id (8 hex for readability)
    req_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:8]
    request_id_ctx_var.set(req_id)

    started = time.perf_counter()

    # Determine the attempt order for THIS request using the shared pointer.
    async with request.app.state.rr_lock:
        start = request.app.state.rr_pos
    order_indices = [(start + off) % N for off in range(N)]
    order = [(i, CREDENTIALS[i]) for i in order_indices]

    # Build path+query and base headers once
    path_and_query = request.url.path
    if request.url.query:
        path_and_query += f"?{request.url.query}"

    base_headers = {k.lower(): v for k, v in request.headers.items()
                    if k.lower() not in HOP_BY_HOP and k.lower() != "host"}
    # scrub any inbound auth
    base_headers.pop("api-key", None)
    base_headers.pop("authorization", None)

    body = await request.body()
    logger.info("Request %s %s (order=%s)",
                request.method, request.url.path,
                ",".join(_host(CREDENTIALS[i][0]) for i in order_indices))

    attempts = []   # for final JSON on total failure
    last_error = None

    async with httpx.AsyncClient() as client:
        for attempt_num, (abs_idx, (endpoint, api_key)) in enumerate(order, start=1):
            t0 = time.perf_counter()
            target_url = f"{endpoint}{path_and_query}"
            headers = dict(base_headers)
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
                upstream = await client.send(req, stream=True)
            except httpx.HTTPError as e:
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                last_error = f"{type(e).__name__}: {e}"
                attempts.append({
                    "endpoint": endpoint,
                    "status": None,
                    "error": type(e).__name__,
                    "message": str(e),
                    "elapsed_ms": elapsed_ms,
                })
                logger.error("Attempt %d transport error: %s", attempt_num, e)
                continue

            status = upstream.status_code

            # Retryable statuses (incl. 404 for missing deployment on that endpoint)
            if status in RETRY_STATUS or status in RETRY_4XX:
                # Snapshot a small body + some headers BEFORE closing
                hdrs = {h: upstream.headers.get(h) for h in ERROR_HEADER_SNAPSHOT if upstream.headers.get(h)}
                try:
                    data = await upstream.aread()
                except Exception:
                    data = b""
                finally:
                    await upstream.aclose()

                ct = (hdrs.get("content-type") or "").lower()
                truncated = len(data) > ERROR_BODY_MAX_BYTES
                preview = data[:ERROR_BODY_MAX_BYTES]

                body_json = None
                body_snippet = None

                # If it's JSON and not truncated, try to parse into an object
                if ("json" in ct) and not truncated:
                    try:
                        body_json = json.loads(preview.decode("utf-8", "replace"))
                    except Exception:
                        body_json = None  # fall back to snippet below

                if body_json is None:
                    # Text-ish content or truncated JSON -> keep a utf-8 snippet
                    try:
                        body_snippet = preview.decode("utf-8", "replace")
                    except Exception:
                        body_snippet = None
                        # If you prefer base64 for binary, use:
                        # import base64
                        # body_snippet = "base64:" + base64.b64encode(preview).decode("ascii")

                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                last_error = f"HTTP {status} from {endpoint}"
                attempts.append({
                    # "endpoint": endpoint,
                    "status": status,
                    "elapsed_ms": elapsed_ms,
                    "headers": hdrs,
                    "content_type": ct,
                    "truncated": truncated,
                    "body_json": body_json,       # JSON object when parsed & not truncated
                    "body_snippet": body_snippet, # text snippet otherwise
                })

                level = logging.ERROR if status >= 500 else logging.WARNING
                logger.log(level, "Attempt %d got HTTP %d from %s; trying next",
                           attempt_num, status, _host(endpoint))
                continue

            # Non-retryable 4xx: return it immediately (don’t rotate pointer)
            if 400 <= status < 500:
                resp_headers = {k: v for k, v in upstream.headers.items()
                                if k.lower() not in HOP_BY_HOP}
                resp_headers["x-request-id"] = req_id
                duration_ms = int((time.perf_counter() - started) * 1000)
                logger.info("Returning non-retryable %d from %s (duration=%dms)",
                            status, _host(endpoint), duration_ms)
                return StreamingResponse(
                    upstream.aiter_raw(),
                    background=BackgroundTask(upstream.aclose),
                    status_code=status,
                    headers=resp_headers,
                    media_type=upstream.headers.get("content-type"),
                )

            # ---- SUCCESS: advance shared pointer to the element AFTER the one that succeeded
            async with request.app.state.rr_lock:
                request.app.state.rr_pos = (abs_idx + 1) % N

            resp_headers = {k: v for k, v in upstream.headers.items()
                            if k.lower() not in HOP_BY_HOP}
            resp_headers["x-request-id"] = req_id

            duration_ms = int((time.perf_counter() - started) * 1000)
            logger.info("Success via %s (status=%d, duration=%dms). Next start=%d",
                        _host(endpoint), status, duration_ms, request.app.state.rr_pos)

            return StreamingResponse(
                upstream.aiter_raw(),
                background=BackgroundTask(upstream.aclose),
                status_code=status,
                headers=resp_headers,
                media_type=upstream.headers.get("content-type"),
            )

    # ---- ALL FAILED: advance pointer by 1 so we don't keep starting at the same first
    async with request.app.state.rr_lock:
        request.app.state.rr_pos = (start + 1) % N

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.error("All upstreams failed after %dms. Next start=%d. Last error: %s",
                 duration_ms, request.app.state.rr_pos, last_error or "unknown error")

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
