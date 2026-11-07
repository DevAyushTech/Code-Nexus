import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class AnalysisReport(Base):
    __tablename__ = "analysis_reports"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    target_hash: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(30))
    risk_score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    findings: Mapped[list["SecurityFinding"]] = relationship(back_populates="report", cascade="all, delete-orphan")
    url_analysis: Mapped["URLAnalysis"] = relationship(back_populates="report", uselist=False)


class URLAnalysis(Base):
    __tablename__ = "url_analyses"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), index=True)
    normalized_url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    report: Mapped[AnalysisReport] = relationship(back_populates="url_analysis")


class TLSAnalysis(Base):
    __tablename__ = "tls_analyses"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ScamAnalysis(Base):
    __tablename__ = "scam_analyses"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(20))
    evidence: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(120))
    explanation: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    report: Mapped[AnalysisReport] = relationship(back_populates="findings")


class ThreatIntelligenceMatch(Base):
    __tablename__ = "threat_intelligence_matches"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), index=True)
    source: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30))
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ThreatReport(Base):
    __tablename__ = "threat_reports"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator: Mapped[str] = mapped_column(Text)
    indicator_hash: Mapped[str] = mapped_column(String(64), index=True)
    report_type: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class BlockchainRecord(Base):
    __tablename__ = "blockchain_records"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_reports.id"), unique=True)
    report_hash: Mapped[str] = mapped_column(String(64), unique=True)
    tx_hash: Mapped[str] = mapped_column(String(100), nullable=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=True)
    contract_address: Mapped[str] = mapped_column(String(42), nullable=True)
    block_number: Mapped[int] = mapped_column(Integer, nullable=True)
    gas_used: Mapped[int] = mapped_column(Integer, nullable=True)
    confirmations: Mapped[int] = mapped_column(Integer, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    error_code: Mapped[str] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(30))


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(30), index=True)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
