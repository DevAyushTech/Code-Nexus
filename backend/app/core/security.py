import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= window_seconds:
                events.popleft()
            if len(events) >= limit:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")
            events.append(now)


limiter = RateLimiter()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _guard(request: Request, bucket: str, limit: int, supplied: str | None) -> None:
    if settings.api_auth_key:
        if not hmac.compare_digest(supplied or "", settings.api_auth_key.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid API key required.")
    client = request.client.host if request.client else "unknown"
    limiter.check(f"{bucket}:{client}", limit, settings.rate_limit_window_seconds)


def url_analysis_guard(request: Request, supplied: str | None = Security(api_key_header)) -> None:
    _guard(request, "url-analysis", settings.url_analysis_rate_limit, supplied)


def message_analysis_guard(request: Request, supplied: str | None = Security(api_key_header)) -> None:
    _guard(request, "message-analysis", settings.message_analysis_rate_limit, supplied)


def threat_report_guard(request: Request, supplied: str | None = Security(api_key_header)) -> None:
    _guard(request, "threat-report", settings.threat_report_rate_limit, supplied)


def api_key_guard(request: Request, supplied: str | None = Security(api_key_header)) -> None:
    if not settings.api_auth_key:
        return
    if not hmac.compare_digest(supplied or "", settings.api_auth_key.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid API key required.")
