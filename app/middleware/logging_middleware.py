from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response
import logging
import time

# Configure logging here
log_file_path = "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        try:
            # Process the request
            response = await call_next(request)
            status_code = response.status_code

        except Exception as e:
            # Handle the exception and log the error
            status_code = 500  # Internal Server Error
            logger.error(f"Error processing request: {e}", exc_info=True)

            # Customize the error response if needed
            response = Response("Internal server error", status_code=status_code)

        process_time = time.time() - start_time

        # Add X-Process-Time header to the response
        response.headers["X-Process-Time"] = f"{process_time:.2f} seconds"

        client_ip = request.client.host

        # Log the request details
        log_dict = {
            'client_ip': client_ip,
            'url': f"{request.url.path}",
            'method': f"{request.method}",
            'status_code': f"{status_code}",
            'process_time': f"{process_time:.2f} seconds",
        }
        logger.info(log_dict)

        return response
