import hmac
import threading
import time
from collections import defaultdict, deque

import httpx
import jwt
from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError

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
bearer_scheme = HTTPBearer(auto_error=False)


class _JWKSCache:
    def __init__(self) -> None:
        self._keys: dict[str, jwt.PyJWK] = {}
        self._lock = threading.Lock()

    def get(self, kid: str, *, refresh: bool = False) -> jwt.PyJWK | None:
        with self._lock:
            if not refresh and kid in self._keys:
                return self._keys[kid]
            response = httpx.get(settings.supabase_jwks_url, timeout=5.0)
            response.raise_for_status()
            payload = response.json()
            keys = payload.get("keys")
            if not isinstance(keys, list):
                raise ValueError("JWKS response did not contain keys.")
            refreshed: dict[str, jwt.PyJWK] = {}
            for item in keys:
                if isinstance(item, dict) and isinstance(item.get("kid"), str):
                    refreshed[item["kid"]] = jwt.PyJWK.from_dict(item)
            self._keys = refreshed
            return self._keys.get(kid)


jwks_cache = _JWKSCache()


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid authentication required.")


def _verify_bearer_token(token: str) -> None:
    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in settings.supabase_jwt_algorithms or algorithm != "ES256" or not isinstance(kid, str):
            raise InvalidTokenError("Unsupported JWT header.")
        key = jwks_cache.get(kid)
        if key is None:
            key = jwks_cache.get(kid, refresh=True)
        if key is None:
            raise InvalidTokenError("Unknown JWT key.")
        if key.algorithm_name != algorithm:
            raise InvalidTokenError("JWT algorithm does not match the signing key.")
        jwt.decode(
            token,
            key.key,
            algorithms=["ES256"],
            audience=settings.supabase_jwt_audience,
            issuer=settings.supabase_jwt_issuer,
            options={"require": ["exp"]},
        )
    except (InvalidTokenError, ValueError, httpx.HTTPError):
        raise _unauthorized() from None


def _authenticate(
    request: Request,
    supplied_api_key: str | None,
    bearer: HTTPAuthorizationCredentials | None,
) -> None:
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        if not authorization.startswith("Bearer ") or bearer is None or not bearer.credentials:
            raise _unauthorized()
        _verify_bearer_token(bearer.credentials)
        return
    configured_api_key = settings.api_auth_key.get_secret_value().strip() if settings.api_auth_key else ""
    if configured_api_key:
        if not hmac.compare_digest(supplied_api_key or "", configured_api_key):
            raise _unauthorized()
        return
    if settings.api_auth_mode == "protected_demo":
        raise _unauthorized()


def _authenticate_request(request: Request) -> None:
    authorization = request.headers.get("Authorization")
    bearer = None
    if authorization is not None:
        if not authorization.startswith("Bearer ") or not authorization[7:]:
            raise _unauthorized()
        bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=authorization[7:])
    _authenticate(request, request.headers.get("X-API-Key"), bearer)


def _guard(
    request: Request,
    bucket: str,
    limit: int,
    supplied: str | None,
    bearer: HTTPAuthorizationCredentials | None,
) -> None:
    _authenticate(request, supplied, bearer)
    client = request.client.host if request.client else "unknown"
    limiter.check(f"{bucket}:{client}", limit, settings.rate_limit_window_seconds)


def _public_demo_guard(request: Request, bucket: str, limit: int) -> None:
    if (
        not settings.public_demo_mode
        or request.headers.get("Authorization") is not None
        or request.headers.get("X-API-Key") is not None
    ):
        _authenticate_request(request)
    client = request.client.host if request.client else "unknown"
    limiter.check(f"{bucket}:{client}", limit, settings.rate_limit_window_seconds)


def public_url_analysis_guard(request: Request) -> None:
    _public_demo_guard(request, "url-analysis", settings.url_analysis_rate_limit)


def public_message_analysis_guard(request: Request) -> None:
    _public_demo_guard(request, "message-analysis", settings.message_analysis_rate_limit)


def public_blockchain_verify_guard(request: Request) -> None:
    _public_demo_guard(request, "blockchain-verify", settings.blockchain_verify_rate_limit)


def url_analysis_guard(
    request: Request,
    supplied: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> None:
    _guard(request, "url-analysis", settings.url_analysis_rate_limit, supplied, bearer)


def message_analysis_guard(
    request: Request,
    supplied: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> None:
    _guard(request, "message-analysis", settings.message_analysis_rate_limit, supplied, bearer)


def threat_report_guard(
    request: Request,
    supplied: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> None:
    _guard(request, "threat-report", settings.threat_report_rate_limit, supplied, bearer)


def api_key_guard(
    request: Request,
    supplied: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> None:
    _authenticate(request, supplied, bearer)
