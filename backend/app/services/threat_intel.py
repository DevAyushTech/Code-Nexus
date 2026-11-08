import httpx
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings
from app.services.provider_evidence import provider_result


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def _safe_evidence(data: dict, exact_match: bool) -> dict:
    threat = data.get("threat")
    return {
        "query_status": data.get("query_status"),
        "url_match": exact_match,
        "threat": threat[:120] if isinstance(threat, str) else None,
        "url_status": data.get("url_status"),
    }


def check_urlhaus(url: str) -> dict:
    if not settings.urlhaus_auth_key:
        return provider_result("URLhaus", "not_configured")
    for attempt in range(2):
        try:
            response = httpx.post(settings.urlhaus_api_url, data={"url": url}, headers={"Auth-Key": settings.urlhaus_auth_key.get_secret_value()}, timeout=settings.request_timeout_seconds)
            if response.status_code >= 500 and attempt == 0:
                continue
            if response.status_code == 429:
                return provider_result("URLhaus", "rate_limited")
            if response.status_code in {401, 403}:
                return provider_result("URLhaus", "error", error="invalid_api_key")
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return provider_result("URLhaus", "inconclusive", error="invalid_response")
            returned_url = data.get("url")
            query_ok = data.get("query_status") == "ok"
            exact_match = isinstance(returned_url, str) and _normalize_url(returned_url) == _normalize_url(url)
            threat = data.get("threat")
            url_status = data.get("url_status")
            match = query_ok and exact_match and bool(threat) and url_status in {"online", "offline"}
            return provider_result(
                "URLhaus",
                "completed",
                match=match,
                confidence=1.0 if match else 0.9,
                evidence=_safe_evidence(data, exact_match),
            )
        except httpx.TimeoutException as exc:
            if attempt == 0:
                continue
            return provider_result("URLhaus", "unavailable", error=type(exc).__name__)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            return provider_result("URLhaus", "error", error=type(exc).__name__)
    return provider_result("URLhaus", "unavailable", error="retry_limit")
