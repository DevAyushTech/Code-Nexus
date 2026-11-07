import hashlib
import threading
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import AnalysisReport, BlockchainRecord, ScamAnalysis, SecurityFinding, ThreatIndicator, ThreatIntelligenceMatch, ThreatReport, TLSAnalysis, URLAnalysis
from app.core.security import api_key_guard, message_analysis_guard, threat_report_guard, url_analysis_guard
from app.schemas.api import AnalysisResponse, BlockchainRegisterRequest, BlockchainRegistrationResponse, BlockchainVerificationResponse, DashboardSummaryResponse, EvidenceSummary, FindingResponse, IntegrationResponse, MessageAnalyzeRequest, ThreatFeedResponse, ThreatReportCreate, ThreatReportResponse, URLAnalyzeRequest
from app.services.ai import explain
from app.services.message_analysis import analyze_message
from app.services.threat_intel import check_urlhaus
from app.services.tls import inspect_tls
from app.services.url_analysis import analyze_url
from app.services.website import inspect_website
from app.services.risk import assess
from app.services.safe_browsing import check_safe_browsing
from app.services.blockchain import BlockchainConfigurationError, BlockchainDependencyError, BlockchainRPCError, BlockchainTransactionError, get_blockchain_service, transition_state

api_router = APIRouter()
_blockchain_registration_lock = threading.Lock()


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_integration(integration: dict) -> dict:
    safe = dict(integration)
    for key in ("url", "final_url"):
        if isinstance(safe.get(key), str):
            safe[key] = _safe_url(safe[key])
    return safe


def _safe_ai_analysis(ai_analysis: dict | None) -> dict | None:
    if not ai_analysis:
        return ai_analysis
    safe = dict(ai_analysis)
    if isinstance(safe.get("extracted_urls"), list):
        safe["extracted_urls"] = [_safe_url(item) if isinstance(item, str) else item for item in safe["extracted_urls"]]
    return safe


def _evidence_summary(findings: list, integrations: list[dict]) -> EvidenceSummary:
    typed = [IntegrationResponse.model_validate(_safe_integration(item)) for item in integrations]
    confirmed = [item for item in typed if item.match is True]
    technical = [item for item in typed if item.source in {"TLS", "passive_website_inspection"}]
    unavailable = [item for item in typed if item.status in {"not_configured", "unavailable", "rate_limited", "error", "inconclusive"}]
    return EvidenceSummary(
        confirmed_matches=confirmed,
        technical_indicators=technical,
        heuristic_findings=[FindingResponse.model_validate(item) for item in findings],
        inconclusive_or_unavailable=unavailable,
    )


def _public_blockchain_error(exc: Exception | str) -> str:
    if isinstance(exc, str):
        return {
            "transaction_reverted": "Blockchain transaction was reverted.",
            "receipt_timeout": "Blockchain receipt confirmation timed out.",
            "receipt_unavailable": "Blockchain receipt is not yet available.",
            "insufficient_confirmations": "Blockchain confirmation depth is insufficient.",
        }.get(exc, "Blockchain operation failed.")
    if isinstance(exc, BlockchainConfigurationError):
        return "Blockchain configuration is invalid."
    if isinstance(exc, BlockchainDependencyError):
        return "Blockchain service is unavailable."
    if isinstance(exc, BlockchainRPCError):
        return "Blockchain network is unavailable."
    if isinstance(exc, BlockchainTransactionError):
        return "Blockchain transaction failed."
    return "Blockchain operation failed."


def canonical_report_hash(report: AnalysisReport) -> str:
    return hashlib.sha256(f"{report.id}:{report.target_hash}:{report.classification}:{report.risk_score}".encode()).hexdigest()


def persist_analysis(db: Session, kind: str, result: dict, integrations: list[dict] | None = None, ai_analysis: dict | None = None) -> AnalysisResponse:
    integrations = [_safe_integration(item) for item in (integrations or [])]
    ai_analysis = _safe_ai_analysis(ai_analysis)
    report = AnalysisReport(kind=kind, target_hash=result["target_hash"], classification=result["classification"], risk_score=result["risk_score"])
    db.add(report)
    db.flush()
    for finding in result["findings"]:
        db.add(SecurityFinding(report_id=report.id, name=finding.name, severity=finding.severity, evidence=finding.evidence, source=finding.source, explanation=finding.explanation, recommendation=finding.recommendation))
    if kind == "url":
        safe_target = _safe_url(result["normalized_url"])
        db.add(URLAnalysis(report_id=report.id, normalized_url=safe_target, domain=result["domain"], data={"scheme": result["scheme"], "query_keys": result["query_keys"]}))
    for integration in integrations:
        if kind == "url" and integration.get("source") not in {"TLS"}:
            db.add(ThreatIntelligenceMatch(report_id=report.id, source=integration["source"], status=integration.get("status", "unavailable"), data=integration))
    if kind == "url":
        tls = next((item for item in integrations or [] if item.get("source") == "TLS"), None)
        if tls:
            db.add(TLSAnalysis(report_id=report.id, data=tls))
        db.add(ThreatIndicator(indicator_type="domain", value_hash=hashlib.sha256(result["domain"].encode()).hexdigest(), metadata_json={"domain": result["domain"]}))
    if kind == "message":
        safe_iocs = dict(result.get("iocs", {}))
        safe_iocs["urls"] = [_safe_url(item) for item in safe_iocs.get("urls", []) if isinstance(item, str)]
        db.add(ScamAnalysis(report_id=report.id, data={"iocs": safe_iocs, "ai_analysis": ai_analysis}))
        for indicator_type, values in result.get("iocs", {}).items():
            for value in values:
                db.add(ThreatIndicator(indicator_type=indicator_type, value_hash=hashlib.sha256(value.encode()).hexdigest(), metadata_json={}))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    target = _safe_url(result["target"]) if kind == "url" else result["target"]
    findings = [FindingResponse.model_validate(f) for f in result["findings"]]
    return AnalysisResponse(id=report.id, kind=kind, target=target, classification=result["classification"], risk_score=result["risk_score"], findings=findings, integrations=integrations, evidence_quality="mixed" if integrations else "deterministic", evidence_summary=_evidence_summary(findings, integrations), ai_analysis=ai_analysis)


@api_router.post("/analyze/url", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(url_analysis_guard)])
def analyze_url_endpoint(payload: URLAnalyzeRequest, db: Session = Depends(get_db)) -> AnalysisResponse:
    try:
        result = analyze_url(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    integration = check_urlhaus(str(payload.url))
    safe_browsing = check_safe_browsing(str(payload.url))
    authoritative_match = bool(integration.get("match") or safe_browsing.get("match"))
    result["risk_score"], result["classification"] = assess(result["findings"], authoritative_match=authoritative_match)
    return persist_analysis(db, "url", result, [integration, safe_browsing, {"source": "TLS", **inspect_tls(result["domain"])}, inspect_website(str(payload.url))])


@api_router.post("/analyze/message", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(message_analysis_guard)])
def analyze_message_endpoint(payload: MessageAnalyzeRequest, db: Session = Depends(get_db)) -> AnalysisResponse:
    try:
        result = analyze_message(payload.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    ai_result = explain([f.__dict__ for f in result["findings"]], payload.content, result["iocs"])
    ai_analysis = ai_result.get("analysis")
    return persist_analysis(db, "message", result, [ai_result], ai_analysis)


@api_router.get("/reports/{report_id}", response_model=AnalysisResponse, dependencies=[Depends(api_key_guard)])
def get_report(report_id: uuid.UUID, db: Session = Depends(get_db)) -> AnalysisResponse:
    report = db.get(AnalysisReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    target = "[message redacted]"
    if report.kind == "url" and report.url_analysis:
        target = report.url_analysis.normalized_url
    scam = db.scalar(select(ScamAnalysis).where(ScamAnalysis.report_id == report.id))
    ai_analysis = _safe_ai_analysis(scam.data.get("ai_analysis")) if scam else None
    integrations = [_safe_integration(match.data) for match in db.scalars(select(ThreatIntelligenceMatch).where(ThreatIntelligenceMatch.report_id == report.id)).all()]
    tls = db.scalar(select(TLSAnalysis).where(TLSAnalysis.report_id == report.id))
    if tls:
        integrations.append(_safe_integration(tls.data))
    findings = [FindingResponse.model_validate(f) for f in report.findings]
    return AnalysisResponse(id=report.id, kind=report.kind, target=target, classification=report.classification, risk_score=report.risk_score, findings=findings, integrations=integrations, evidence_quality="mixed" if integrations else "deterministic", evidence_summary=_evidence_summary(findings, integrations), ai_analysis=ai_analysis)


@api_router.get("/dashboard/summary", response_model=DashboardSummaryResponse, dependencies=[Depends(api_key_guard)])
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummaryResponse:
    total = db.scalar(select(func.count(AnalysisReport.id))) or 0
    classifications = dict(db.execute(select(AnalysisReport.classification, func.count()).group_by(AnalysisReport.classification)).all())
    return {"total": total, "total_reports": total, "classifications": classifications}


@api_router.get("/threats", response_model=ThreatFeedResponse, dependencies=[Depends(api_key_guard)])
def list_threats(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db)) -> ThreatFeedResponse:
    items = db.scalars(select(ThreatReport).order_by(ThreatReport.created_at.desc()).offset(skip).limit(limit)).all()
    return {"items": [ThreatReportResponse.model_validate(item) for item in items], "skip": skip, "limit": limit}


@api_router.post("/threat-reports", response_model=ThreatReportResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(threat_report_guard)])
def create_threat_report(payload: ThreatReportCreate, db: Session = Depends(get_db)) -> ThreatReportResponse:
    item = ThreatReport(indicator="[redacted]", indicator_hash=hashlib.sha256(payload.indicator.encode()).hexdigest(), report_type=payload.report_type, description=payload.description)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@api_router.get("/threat-reports/{report_id}", response_model=ThreatReportResponse, dependencies=[Depends(api_key_guard)])
def get_threat_report(report_id: uuid.UUID, db: Session = Depends(get_db)) -> ThreatReportResponse:
    item = db.get(ThreatReport, report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Threat report not found.")
    return item


@api_router.post("/blockchain/register", response_model=BlockchainRegistrationResponse, dependencies=[Depends(api_key_guard)])
def register_blockchain(payload: BlockchainRegisterRequest, db: Session = Depends(get_db)) -> BlockchainRegistrationResponse:
    report = db.get(AnalysisReport, payload.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    digest = canonical_report_hash(report)
    blockchain = get_blockchain_service()
    existing = db.scalar(select(BlockchainRecord).where(BlockchainRecord.report_id == report.id))
    if existing and blockchain.config.blockchain_mode == "mock":
        return {
            "status": existing.status,
            "mode": "sepolia" if existing.chain_id else "mock",
            "on_chain": bool(existing.tx_hash and existing.block_number and existing.status in {"confirming", "confirmed"}),
            "report_id": report.id,
            "report_hash": existing.report_hash,
            "tx_hash": existing.tx_hash,
            "chain_id": existing.chain_id,
            "contract_address": existing.contract_address,
            "block_number": existing.block_number,
            "gas_used": existing.gas_used,
            "confirmations": existing.confirmations,
        }
    if blockchain.config.blockchain_mode == "sepolia":
        with _blockchain_registration_lock:
            existing = db.scalar(select(BlockchainRecord).where(BlockchainRecord.report_id == report.id))
            if existing and existing.tx_hash:
                record = existing
                try:
                    result = blockchain.adapter.inspect_transaction(existing.tx_hash, existing.submitted_at)
                except (BlockchainConfigurationError, BlockchainDependencyError, BlockchainRPCError) as exc:
                    raise HTTPException(status_code=503, detail=_public_blockchain_error(exc)) from exc
                existing.status = transition_state(existing.status, result.status)
                existing.block_number = result.block_number or existing.block_number
                existing.gas_used = result.gas_used or existing.gas_used
                existing.confirmations = result.confirmations
                existing.confirmed_at = result.confirmed_at
                existing.error_message = _public_blockchain_error(result.error_code) if result.error_code else None
                existing.error_code = result.error_code
                db.commit()
            else:
                if existing and existing.status == "pending":
                    return {
                        "status": "pending",
                        "mode": "sepolia",
                        "on_chain": False,
                        "report_id": report.id,
                        "report_hash": existing.report_hash,
                        "tx_hash": None,
                        "chain_id": existing.chain_id,
                        "contract_address": existing.contract_address,
                        "explorer_url": None,
                    }
                now = datetime.now(timezone.utc)
                record = existing or BlockchainRecord(
                    report_id=report.id,
                    report_hash=digest,
                    status="pending",
                    chain_id=blockchain.config.blockchain_chain_id,
                    contract_address=blockchain.config.blockchain_contract_address,
                )
                db.add(record)
                db.commit()

                def persist_submission(tx_hash: str, submitted_at: datetime) -> None:
                    record.tx_hash = tx_hash
                    record.status = "submitted"
                    record.submitted_at = submitted_at
                    record.error_code = None
                    db.commit()

                try:
                    result = blockchain.adapter.register_hash(digest, on_submitted=persist_submission)
                except (BlockchainConfigurationError, BlockchainDependencyError) as exc:
                    record.status = transition_state(record.status, "failed")
                    record.error_code = "configuration_error"
                    record.error_message = _public_blockchain_error(exc)
                    db.commit()
                    raise HTTPException(status_code=503, detail=_public_blockchain_error(exc)) from exc
                except BlockchainRPCError as exc:
                    record.status = transition_state(record.status, "failed")
                    record.error_code = "rpc_error"
                    record.error_message = _public_blockchain_error(exc)
                    db.commit()
                    raise HTTPException(status_code=502, detail=_public_blockchain_error(exc)) from exc
                except BlockchainTransactionError as exc:
                    record.status = transition_state(record.status, "failed")
                    record.error_code = "transaction_error"
                    record.error_message = _public_blockchain_error(exc)
                    db.commit()
                    raise HTTPException(status_code=502, detail=_public_blockchain_error(exc)) from exc
                record.status = transition_state(record.status, result.status)
                record.tx_hash = result.tx_hash or record.tx_hash
                record.chain_id = result.chain_id
                record.contract_address = result.contract_address
                record.block_number = result.block_number
                record.gas_used = result.gas_used
                record.confirmations = result.confirmations
                record.submitted_at = result.submitted_at or record.submitted_at or now
                record.confirmed_at = result.confirmed_at
                record.error_message = _public_blockchain_error(result.error_code) if result.error_code else None
                record.error_code = result.error_code
                db.commit()
            explorer_url = f"https://sepolia.etherscan.io/tx/{record.tx_hash}" if record.tx_hash and record.chain_id == 11155111 else None
            return {
                "status": record.status,
                "mode": "sepolia",
                "on_chain": bool(record.tx_hash and record.block_number and record.status in {"confirming", "confirmed"}),
                "report_id": report.id,
                "report_hash": record.report_hash,
                "tx_hash": record.tx_hash,
                "chain_id": record.chain_id,
                "contract_address": record.contract_address,
                "block_number": record.block_number,
                "gas_used": record.gas_used,
                "confirmations": record.confirmations,
                "explorer_url": explorer_url,
            }
    record = BlockchainRecord(report_id=report.id, report_hash=digest, status="mock")
    db.add(record)
    db.commit()
    return {"status": "mock", "mode": "mock", "on_chain": False, "report_id": report.id, "report_hash": digest, "tx_hash": None}


@api_router.get("/blockchain/verify/{report_id}", response_model=BlockchainVerificationResponse, dependencies=[Depends(api_key_guard)])
def verify_blockchain(report_id: uuid.UUID, db: Session = Depends(get_db)) -> BlockchainVerificationResponse:
    report = db.get(AnalysisReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    digest = canonical_report_hash(report)
    record = db.scalar(select(BlockchainRecord).where(BlockchainRecord.report_id == report_id))
    blockchain = get_blockchain_service()
    if blockchain.config.blockchain_mode == "mock":
        return {
            "verified": False,
            "status": "not_registered" if not record else "not_registered",
            "mode": "mock",
            "verification_source": "local_mock",
            "on_chain": False,
            "report_hash": digest,
            "tx_hash": record.tx_hash if record else None,
            "chain_id": None,
            "contract_address": None,
            "reporter": None,
            "on_chain_timestamp": None,
            "confirmations": None,
        }
    try:
        result = blockchain.adapter.verify_commitment(digest, record.tx_hash if record else None)
    except BlockchainConfigurationError as exc:
        return {"verified": False, "status": "invalid_configuration", "mode": "sepolia", "verification_source": "sepolia", "on_chain": False, "report_hash": digest, "tx_hash": record.tx_hash if record else None, "error_code": "invalid_configuration"}
    except (BlockchainDependencyError, BlockchainRPCError) as exc:
        return {"verified": False, "status": "unavailable", "mode": "sepolia", "verification_source": "sepolia", "on_chain": False, "report_hash": digest, "tx_hash": record.tx_hash if record else None, "error_code": "rpc_unavailable"}
    local_mismatch = bool(record and record.report_hash != digest)
    verified = result.verified and not local_mismatch
    status_value = "mismatch" if local_mismatch else result.status
    return {
        "verified": verified,
        "status": status_value,
        "mode": "sepolia",
        "verification_source": "sepolia",
        "on_chain": result.registered,
        "report_hash": digest,
        "tx_hash": record.tx_hash if record else None,
        "chain_id": result.chain_id,
        "contract_address": result.contract_address,
        "reporter": result.reporter,
        "on_chain_timestamp": result.on_chain_timestamp,
        "confirmations": result.confirmations,
        "receipt_status": result.receipt_status,
        "block_number": result.block_number,
        "error_code": result.error_code,
    }
