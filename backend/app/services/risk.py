from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str
    evidence: str
    source: str
    explanation: str
    recommendation: str
    points: int
    confidence: float = 0.75


def assess(findings: list[Finding], authoritative_match: bool = False) -> tuple[int, str]:
    score = min(100, max(0, sum(f.points for f in findings)))
    if authoritative_match:
        return score, "CONFIRMED_MALICIOUS"
    if not findings:
        return 0, "INCONCLUSIVE"
    if score >= 70:
        return score, "HIGH"
    if score >= 35:
        return score, "SUSPICIOUS"
    return score, "LOW"
