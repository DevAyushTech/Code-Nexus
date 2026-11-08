import httpx

from app.core.config import settings
from app.services.provider_evidence import provider_result


def _safe_matches(matches: list[object]) -> list[dict[str, str]]:
    safe_fields = ("threatType", "platformType", "threatEntryType")
    return [
        safe_match
        for match in matches
        if isinstance(match, dict)
        and (safe_match := {field: value for field in safe_fields if isinstance(value := match.get(field), str)})
    ]


def check_safe_browsing(url: str) -> dict:
    if not settings.google_safe_browsing_key:
        return provider_result("Google Safe Browsing", "not_configured")
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
                return provider_result("Google Safe Browsing", "error", error="invalid_api_key")
            if response.status_code == 429:
                return provider_result("Google Safe Browsing", "rate_limited")
            if response.status_code >= 400:
                return provider_result("Google Safe Browsing", "error", error=f"http_{response.status_code}")
            data = response.json()
            if not isinstance(data, dict):
                return provider_result("Google Safe Browsing", "inconclusive", error="invalid_response")
            matches = data.get("matches", [])
            if not isinstance(matches, list):
                return provider_result("Google Safe Browsing", "inconclusive", error="invalid_response")
            safe_matches = _safe_matches(matches)
            if matches and not safe_matches:
                return provider_result("Google Safe Browsing", "inconclusive", error="invalid_match")
            return provider_result(
                "Google Safe Browsing",
                "completed",
                match=bool(safe_matches),
                confidence=1.0 if safe_matches else 0.9,
                evidence=safe_matches,
            )
        except httpx.TimeoutException:
            if attempt == 0:
                continue
            return provider_result("Google Safe Browsing", "unavailable", error="timeout")
        except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
            return provider_result("Google Safe Browsing", "error", error=type(exc).__name__)
    return provider_result("Google Safe Browsing", "unavailable")
