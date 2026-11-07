from datetime import datetime, timezone
from typing import Any


def provider_result(
    source: str,
    status: str,
    *,
    match: bool = False,
    confidence: float = 0.0,
    evidence: Any = None,
    error: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source": source,
        "status": status,
        "match": match,
        "confidence": max(0.0, min(1.0, confidence)),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if evidence is not None:
        result["evidence"] = evidence
    if error is not None:
        result["error"] = error
    return result
