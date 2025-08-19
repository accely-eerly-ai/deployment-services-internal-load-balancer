from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

import os
import uuid
import time
import logging
import contextvars


# ---------- Request ID plumbing ----------
request_id_ctx_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Ensure every record has request_id
        try:
            record.request_id = request_id_ctx_var.get()
        except LookupError:
            record.request_id = "-"
        return True

def init_logging(log_file_path: str | None = "app.log") -> None:
    """
    Initializes logging with LOG_LEVEL env support and a RequestIdFilter.
    Adds both stream and optional file handlers.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"

    # Configure root handlers explicitly so we can attach the filter.
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file_path:
        handlers.append(logging.FileHandler(log_file_path))

    logging.basicConfig(level=level, format=fmt, handlers=handlers)

    f = RequestIdFilter()
    root = logging.getLogger()
    for h in root.handlers:
        h.addFilter(f)

    # Also add the filter to the named logger used below
    logging.getLogger("azure-proxy").addFilter(f)

# Call once at import time
init_logging()
logger = logging.getLogger("azure-proxy")


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Get or create a request ID; propagate across logs + response headers.
        incoming_id = request.headers.get("X-Request-ID")
        req_id = incoming_id or str(uuid.uuid4())

        # Bind the request_id to this context for all log records in this request
        token = request_id_ctx_var.set(req_id)
        try:
            try:
                response = await call_next(request)
                status_code = response.status_code
            except Exception as e:
                status_code = 500
                logger.error("Unhandled error processing request", exc_info=True)
                response = Response("Internal server error", status_code=status_code)

            process_time = time.time() - start_time

            # Response headers
            response.headers["X-Process-Time"] = f"{process_time:.2f} seconds"
            response.headers["X-Request-ID"] = req_id

            # Log details
            client_ip = request.client.host if request.client else "-"
            ua = request.headers.get("User-Agent", "-")
            logger.info(
                "client_ip=%s method=%s path=%s status=%s duration=%.2fs ua=%s",
                client_ip,
                request.method,
                request.url.path,
                status_code,
                process_time,
                ua,
            )

            return response
        finally:
            # Restore previous context (important for worker reuse)
            request_id_ctx_var.reset(token)
