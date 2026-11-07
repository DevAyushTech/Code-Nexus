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


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str | None = None
    status: str
    match: bool | None = None
    evidence: Any | None = None
    error: str | None = None


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    kind: str
    target: str
    classification: str
    risk_score: int
    findings: list[FindingResponse]
    integrations: list[IntegrationResponse] = []
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


class BlockchainRegistrationResponse(BaseModel):
    status: str
    mode: str
    on_chain: bool
    report_id: uuid.UUID
    report_hash: str
    tx_hash: str | None = None
    chain_id: int | None = None
    contract_address: str | None = None
    block_number: int | None = None
    gas_used: int | None = None
    confirmations: int | None = None
    explorer_url: str | None = None


class BlockchainVerificationResponse(BaseModel):
    verified: bool
    status: str
    mode: str
    verification_source: str
    on_chain: bool
    report_hash: str
    tx_hash: str | None = None
    chain_id: int | None = None
    contract_address: str | None = None
    reporter: str | None = None
    on_chain_timestamp: int | None = None
    confirmations: int | None = None
    receipt_status: int | None = None
    block_number: int | None = None
    error_code: str | None = None


class ThreatReportCreate(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    report_type: Literal["url", "domain", "message", "other"]
    description: str = Field(min_length=1, max_length=10_000)


class BlockchainRegisterRequest(BaseModel):
    report_id: uuid.UUID
