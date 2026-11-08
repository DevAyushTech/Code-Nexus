import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unavailable")
        logger.exception("Unhandled request error", extra={"path": request.url.path, "request_id": request_id})
        response = JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "An internal error occurred.", "request_id": request_id}})
        response.headers["X-Request-ID"] = request_id
        return response
