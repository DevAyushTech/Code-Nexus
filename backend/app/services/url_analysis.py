import hashlib
import ipaddress
import re
from urllib.parse import parse_qs, urlparse

from app.services.risk import Finding, assess
from app.services.ssrf import validate_public_url

SUSPICIOUS_WORDS = {"login", "verify", "secure", "wallet", "bonus", "urgent", "account", "password", "kyc"}


def analyze_url(raw_url: str) -> dict:
    host, scheme = validate_public_url(raw_url)
    parsed = urlparse(raw_url)
    findings: list[Finding] = []
    labels = [part for part in host.split(".") if part]
    lower_url = raw_url.lower()
    keywords = sorted(word for word in SUSPICIOUS_WORDS if word in lower_url)
    if keywords:
        findings.append(Finding("Suspicious URL keywords", "medium", ", ".join(keywords), "deterministic", "The URL contains terms frequently used in credential or payment lures.", "Verify the organization through an independently known channel.", min(25, 8 * len(keywords))))
    try:
        ipaddress.ip_address(host)
        findings.append(Finding("IP-based URL", "medium", host, "deterministic", "The URL uses a numeric address instead of a stable domain identity.", "Do not enter credentials unless the destination is independently verified.", 20))
    except ValueError:
        pass
    if any(ord(char) > 127 for char in host):
        findings.append(Finding("Internationalized hostname", "low", host, "deterministic", "Non-ASCII hostname characters can be used in homograph attacks.", "Check the registered domain and use a trusted bookmark.", 15))
    if len(labels) > 4:
        findings.append(Finding("Deep subdomain structure", "low", host, "deterministic", "An unusually deep hostname can obscure the effective registered domain.", "Inspect the registrable domain before trusting the page.", 8))
    if parsed.query and len(parsed.query) > 400:
        findings.append(Finding("Large query string", "low", f"{len(parse_qs(parsed.query))} query keys", "deterministic", "A large query string may contain tracking or obfuscated data.", "Avoid sharing sensitive query parameters.", 5))
    score, classification = assess(findings)
    return {
        "target": raw_url,
        "normalized_url": parsed._replace(fragment="").geturl(),
        "domain": host,
        "scheme": scheme,
        "query_keys": sorted(parse_qs(parsed.query).keys()),
        "findings": findings,
        "risk_score": score,
        "classification": classification,
        "target_hash": hashlib.sha256(raw_url.encode()).hexdigest(),
    }


def extract_iocs(content: str) -> dict[str, list[str]]:
    return {
        "urls": re.findall(r"https?://[^\s<>\"]+", content),
        "emails": re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", content, re.I),
        "phone_numbers": re.findall(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)", content),
    }
