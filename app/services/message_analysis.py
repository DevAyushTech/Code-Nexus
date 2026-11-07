import hashlib
import re

from app.services.risk import Finding, assess
from app.services.url_analysis import extract_iocs


def analyze_message(content: str) -> dict:
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
    score, classification = assess(findings)
    return {"target": "[message redacted]", "target_hash": hashlib.sha256(content.encode()).hexdigest(), "iocs": extract_iocs(content), "findings": findings, "risk_score": score, "classification": classification}
