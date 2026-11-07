import httpx

from app.core.config import settings


def check_safe_browsing(url: str) -> dict:
    if not settings.google_safe_browsing_key:
        return {"source": "Google Safe Browsing", "status": "not_configured", "match": False}
    body = {
        "client": {"clientId": "nexus-threat-intelligence", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    for attempt in range(2):
        try:
            response = httpx.post(settings.google_safe_browsing_url, params={"key": settings.google_safe_browsing_key.get_secret_value()}, json=body, timeout=settings.request_timeout_seconds)
            if response.status_code >= 500 and attempt == 0:
                continue
            if response.status_code in {401, 403}:
                return {"source": "Google Safe Browsing", "status": "error", "match": False, "error": "invalid_api_key"}
            if response.status_code == 429:
                return {"source": "Google Safe Browsing", "status": "rate_limited", "match": False}
            if response.status_code >= 400:
                return {"source": "Google Safe Browsing", "status": "error", "match": False, "error": f"http_{response.status_code}"}
            data = response.json()
            matches = data.get("matches", [])
            if not isinstance(matches, list):
                return {"source": "Google Safe Browsing", "status": "error", "match": False, "error": "invalid_response"}
            return {"source": "Google Safe Browsing", "status": "completed", "match": bool(matches), "evidence": matches}
        except httpx.TimeoutException:
            if attempt == 0:
                continue
            return {"source": "Google Safe Browsing", "status": "unavailable", "match": False, "error": "timeout"}
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            return {"source": "Google Safe Browsing", "status": "error", "match": False, "error": type(exc).__name__}
    return {"source": "Google Safe Browsing", "status": "unavailable", "match": False}
