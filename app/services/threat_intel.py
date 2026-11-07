import httpx
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def check_urlhaus(url: str) -> dict:
    if not settings.urlhaus_auth_key:
        return {"source": "URLhaus", "status": "not_configured", "match": False}
    for attempt in range(2):
        try:
            response = httpx.post(settings.urlhaus_api_url, data={"url": url}, headers={"Auth-Key": settings.urlhaus_auth_key.get_secret_value()}, timeout=settings.request_timeout_seconds)
            if response.status_code >= 500 and attempt == 0:
                continue
            response.raise_for_status()
            data = response.json()
            returned_url = data.get("url")
            query_ok = data.get("query_status") == "ok"
            exact_match = isinstance(returned_url, str) and _normalize_url(returned_url) == _normalize_url(url)
            threat = data.get("threat")
            url_status = data.get("url_status")
            match = query_ok and exact_match and bool(threat) and url_status in {"online", "offline"}
            return {
                "source": "URLhaus",
                "status": "completed",
                "match": match,
                "evidence": {"query_status": data.get("query_status"), "url_match": exact_match, "threat": threat, "url_status": url_status},
            }
        except httpx.TimeoutException as exc:
            if attempt == 0:
                continue
            return {"source": "URLhaus", "status": "unavailable", "match": False, "error": type(exc).__name__}
        except (httpx.HTTPError, ValueError) as exc:
            return {"source": "URLhaus", "status": "error", "match": False, "error": type(exc).__name__}
    return {"source": "URLhaus", "status": "unavailable", "match": False, "error": "retry_limit"}
