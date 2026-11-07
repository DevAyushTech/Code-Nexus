import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

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


def _guard(request: Request, bucket: str, limit: int) -> None:
    if settings.api_auth_key:
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied, settings.api_auth_key.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid API key required.")
    client = request.client.host if request.client else "unknown"
    limiter.check(f"{bucket}:{client}", limit, settings.rate_limit_window_seconds)


def url_analysis_guard(request: Request) -> None:
    _guard(request, "url-analysis", settings.url_analysis_rate_limit)


def message_analysis_guard(request: Request) -> None:
    _guard(request, "message-analysis", settings.message_analysis_rate_limit)


def threat_report_guard(request: Request) -> None:
    _guard(request, "threat-report", settings.threat_report_rate_limit)


def api_key_guard(request: Request) -> None:
    if not settings.api_auth_key:
        return
    supplied = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(supplied, settings.api_auth_key.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid API key required.")
