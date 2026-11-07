import httpx
from pydantic import SecretStr

from app.core.config import settings
from app.services.safe_browsing import check_safe_browsing
from app.services.threat_intel import check_urlhaus


URL = "https://example.com/path?token=private-value"


def provider_response(status_code: int, **kwargs) -> httpx.Response:
    return httpx.Response(status_code, request=httpx.Request("POST", "https://provider.test"), **kwargs)


def configure_providers(monkeypatch):
    monkeypatch.setattr(settings, "urlhaus_auth_key", SecretStr("urlhaus-test-key"))
    monkeypatch.setattr(settings, "google_safe_browsing_key", SecretStr("google-test-key"))


def test_urlhaus_malicious_match_is_normalized(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, json={
        "query_status": "ok",
        "url": URL,
        "threat": "malware",
        "url_status": "online",
        "private_field": "must not escape",
    })
    monkeypatch.setattr("app.services.threat_intel.httpx.post", lambda *args, **kwargs: response)

    result = check_urlhaus(URL)

    assert result["status"] == "completed"
    assert result["match"] is True
    assert result["evidence"] == {
        "query_status": "ok",
        "url_match": True,
        "threat": "malware",
        "url_status": "online",
    }
    assert "private-value" not in str(result)


def test_urlhaus_clean_url(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, json={"query_status": "no_results"})
    monkeypatch.setattr("app.services.threat_intel.httpx.post", lambda *args, **kwargs: response)

    result = check_urlhaus(URL)

    assert result["status"] == "completed"
    assert result["match"] is False


def test_urlhaus_rate_limit_and_server_error_retry(monkeypatch):
    configure_providers(monkeypatch)
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return provider_response(503)
        return provider_response(429)

    monkeypatch.setattr("app.services.threat_intel.httpx.post", fake_post)

    result = check_urlhaus(URL)

    assert result == {"source": "URLhaus", "status": "rate_limited", "match": False}
    assert len(calls) == 2
    assert all(call["timeout"] == settings.request_timeout_seconds for call in calls)


def test_urlhaus_timeout_is_bounded(monkeypatch):
    configure_providers(monkeypatch)
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        raise httpx.TimeoutException("provider timeout")

    monkeypatch.setattr("app.services.threat_intel.httpx.post", fake_post)

    result = check_urlhaus(URL)

    assert result["status"] == "unavailable"
    assert result["match"] is False
    assert len(calls) == 2


def test_urlhaus_invalid_json_is_error(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, content=b"not-json")
    monkeypatch.setattr("app.services.threat_intel.httpx.post", lambda *args, **kwargs: response)

    result = check_urlhaus(URL)

    assert result["status"] == "error"
    assert result["match"] is False


def test_urlhaus_invalid_credentials_are_error(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(401)
    monkeypatch.setattr("app.services.threat_intel.httpx.post", lambda *args, **kwargs: response)

    result = check_urlhaus(URL)

    assert result == {"source": "URLhaus", "status": "error", "match": False, "error": "HTTPStatusError"}


def test_safe_browsing_malicious_match_is_sanitized(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, json={"matches": [{
        "threatType": "SOCIAL_ENGINEERING",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL",
        "threat": {"url": URL},
    }]})
    monkeypatch.setattr("app.services.safe_browsing.httpx.post", lambda *args, **kwargs: response)

    result = check_safe_browsing(URL)

    assert result["status"] == "completed"
    assert result["match"] is True
    assert result["evidence"] == [{
        "threatType": "SOCIAL_ENGINEERING",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL",
    }]
    assert "private-value" not in str(result)


def test_safe_browsing_clean_url(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, json={})
    monkeypatch.setattr("app.services.safe_browsing.httpx.post", lambda *args, **kwargs: response)

    result = check_safe_browsing(URL)

    assert result["status"] == "completed"
    assert result["match"] is False
    assert result["evidence"] == []


def test_safe_browsing_invalid_credentials(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(403)
    monkeypatch.setattr("app.services.safe_browsing.httpx.post", lambda *args, **kwargs: response)

    result = check_safe_browsing(URL)

    assert result == {"source": "Google Safe Browsing", "status": "error", "match": False, "error": "invalid_api_key"}


def test_safe_browsing_rate_limit(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(429)
    monkeypatch.setattr("app.services.safe_browsing.httpx.post", lambda *args, **kwargs: response)

    result = check_safe_browsing(URL)

    assert result == {"source": "Google Safe Browsing", "status": "rate_limited", "match": False}


def test_safe_browsing_server_error_retries_then_unavailable(monkeypatch):
    configure_providers(monkeypatch)
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        return provider_response(503)

    monkeypatch.setattr("app.services.safe_browsing.httpx.post", fake_post)

    result = check_safe_browsing(URL)

    assert result["status"] == "error"
    assert result["error"] == "http_503"
    assert len(calls) == 2


def test_safe_browsing_timeout_is_bounded(monkeypatch):
    configure_providers(monkeypatch)
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        raise httpx.TimeoutException("provider timeout")

    monkeypatch.setattr("app.services.safe_browsing.httpx.post", fake_post)

    result = check_safe_browsing(URL)

    assert result == {
        "source": "Google Safe Browsing",
        "status": "unavailable",
        "match": False,
        "error": "timeout",
    }
    assert len(calls) == 2


def test_safe_browsing_invalid_json_is_error(monkeypatch):
    configure_providers(monkeypatch)
    response = provider_response(200, content=b"not-json")
    monkeypatch.setattr("app.services.safe_browsing.httpx.post", lambda *args, **kwargs: response)

    result = check_safe_browsing(URL)

    assert result["status"] == "error"
    assert result["error"] == "JSONDecodeError"
