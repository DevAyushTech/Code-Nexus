import pytest

from app.services.message_analysis import analyze_message
from app.services.ssrf import UnsafeURL, validate_public_url
from app.services.url_analysis import analyze_url


@pytest.mark.parametrize("url", [
    "https://example.com/secure-login/verify-account?urgent=true",
    "https://example.com/wallet-bonus/kyc",
    "https://example.com/password-reset",
])
def test_suspicious_urls(url: str) -> None:
    result = analyze_url(url)
    assert result["risk_score"] > 0
    assert result["findings"]


@pytest.mark.parametrize("url", ["https://example.com", "https://www.python.org", "https://www.rfc-editor.org"])
def test_benign_urls_are_not_high_by_keyword_alone(url: str) -> None:
    result = analyze_url(url)
    assert result["classification"] in {"LOW", "INCONCLUSIVE", "SUSPICIOUS"}
    assert result["classification"] != "CONFIRMED_MALICIOUS"


def test_message_detects_social_engineering() -> None:
    result = analyze_message("Urgent: pay with a gift card and send your verification code immediately.")
    assert result["classification"] in {"SUSPICIOUS", "HIGH"}
    assert result["iocs"]["urls"] == []


def test_message_detects_suspicious_links_and_impersonation() -> None:
    result = analyze_message("Official security team: verify your account at https://bit.ly/secure-login immediately.")
    names = {finding.name for finding in result["findings"]}
    assert {"Suspicious links", "Possible impersonation"} <= names
    assert 0 <= result["risk_score"] <= 100


def test_empty_message_is_rejected() -> None:
    with pytest.raises(ValueError):
        analyze_message("")


def test_risk_score_is_bounded_for_many_findings() -> None:
    result = analyze_message("urgent immediately act now payment fee gift card crypto password otp login verify security team https://bit.ly/login")
    assert result["risk_score"] == 100


@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data"])
def test_ssrf_destinations_are_blocked(url: str) -> None:
    with pytest.raises(UnsafeURL):
        validate_public_url(url)
