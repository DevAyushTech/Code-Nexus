import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class URLAnalyzeRequest(BaseModel):
    url: HttpUrl


class MessageAnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50_000)


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    severity: str
    evidence: str
    source: str
    explanation: str
    recommendation: str
    confidence: float = 0.0


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    kind: str
    target: str
    classification: str
    risk_score: int
    findings: list[FindingResponse]
    integrations: list[dict[str, Any]] = []
    evidence_quality: str = "deterministic"
    ai_analysis: dict[str, Any] | None = None


class DashboardSummaryResponse(BaseModel):
    total: int
    total_reports: int
    classifications: dict[str, int]


class ThreatReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    report_type: str
    description: str
    created_at: Any


class ThreatFeedResponse(BaseModel):
    items: list[ThreatReportResponse]
    skip: int
    limit: int


class ThreatReportCreate(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    report_type: Literal["url", "domain", "message", "other"]
    description: str = Field(min_length=1, max_length=10_000)


class BlockchainRegisterRequest(BaseModel):
    report_id: uuid.UUID
