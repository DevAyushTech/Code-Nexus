import hashlib
import re
from urllib.parse import urlparse

from app.services.risk import Finding, assess
from app.services.url_analysis import extract_iocs


def analyze_message(content: str) -> dict:
    if not content or not content.strip():
        raise ValueError("Message content must not be empty.")
    findings: list[Finding] = []
    lower = content.lower()
    urgency = ["urgent", "immediately", "within 24 hours", "last warning", "act now"]
    payment = ["gift card", "crypto", "wire transfer", "payment", "fee"]
    credential = ["password", "otp", "verification code", "log in", "login"]
    for name, terms, points, explanation in [
        ("Urgency manipulation", urgency, 18, "Urgency can pressure recipients into bypassing normal verification."),
        ("Suspicious payment request", payment, 25, "Unexpected payment instructions are a common social-engineering signal."),
        ("Credential harvesting language", credential, 25, "The message requests or references credentials or authentication secrets."),
    ]:
        matches = [term for term in terms if term in lower]
        if matches:
            findings.append(Finding(name, "medium", ", ".join(matches), "deterministic", explanation, "Pause and verify using a known official contact method.", points))
    urls = extract_iocs(content)["urls"]
    suspicious_links = []
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}
    for value in urls:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if host in shorteners or any(term in value.lower() for term in ("login", "verify", "password", "wallet", "secure")):
            suspicious_links.append(host or "malformed URL")
    if suspicious_links:
        findings.append(Finding("Suspicious links", "medium", ", ".join(sorted(set(suspicious_links))), "deterministic", "Links use shortening or credential-related language commonly seen in phishing messages.", "Open links only after independently verifying the sender and destination.", 25))
    impersonation_terms = ("security team", "support team", "administrator", "account team", "official notice")
    impersonation_matches = [term for term in impersonation_terms if term in lower]
    if impersonation_matches:
        findings.append(Finding("Possible impersonation", "medium", ", ".join(impersonation_matches), "deterministic", "The message presents itself as an authority or service team without independently verifiable identity.", "Contact the organization through a trusted channel.", 20))
    score, classification = assess(findings)
    return {"target": "[message redacted]", "target_hash": hashlib.sha256(content.encode()).hexdigest(), "iocs": extract_iocs(content), "findings": findings, "risk_score": score, "classification": classification}
