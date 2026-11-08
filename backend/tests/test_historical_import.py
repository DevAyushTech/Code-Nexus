import sqlite3
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.models import (
    AnalysisReport,
    BlockchainRecord,
    ScamAnalysis,
    SecurityFinding,
    TLSAnalysis,
    ThreatIntelligenceMatch,
    URLAnalysis,
)
from scripts.import_historical_report import (
    EXPECTED_CHAIN_ID,
    EXPECTED_CONTRACT_ADDRESS,
    EXPECTED_REPORT_HASH,
    EXPECTED_TX_HASH,
    ImportError,
    apply_plan,
    canonical_report_hash,
    load_source_plan,
)

REPORT_ID = uuid.UUID("14c7f538-f2d0-4320-865d-15b2d2631704")
TARGET_HASH = "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7"


def _source_engine(path: Path):
    return create_engine(
        "sqlite+pysqlite://",
        creator=lambda: sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True),
    )


def _make_source(path: Path):
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as session:
        report = AnalysisReport(
            id=REPORT_ID,
            kind="url",
            target_hash=TARGET_HASH,
            classification="INCONCLUSIVE",
            risk_score=0,
        )
        session.add(report)
        session.flush()
        session.add(URLAnalysis(
            id=uuid.uuid4(), report_id=report.id, normalized_url="https://example.com",
            domain="example.com", data={"status": "completed"},
        ))
        session.add(TLSAnalysis(
            id=uuid.uuid4(), report_id=report.id, data={"valid": True},
        ))
        session.add(ThreatIntelligenceMatch(
            id=uuid.uuid4(), report_id=report.id, source="URLhaus",
            status="completed", data={"match": False},
        ))
        session.add(SecurityFinding(
            id=uuid.uuid4(), report_id=report.id, name="Historical finding",
            severity="low", evidence="fixture", source="fixture",
            explanation="Fixture evidence", recommendation="Review",
        ))
        session.add(ScamAnalysis(
            id=uuid.uuid4(), report_id=report.id, data={"status": "completed"},
        ))
        session.add(BlockchainRecord(
            id=uuid.uuid4(), report_id=report.id, report_hash=EXPECTED_REPORT_HASH,
            tx_hash=EXPECTED_TX_HASH, chain_id=EXPECTED_CHAIN_ID,
            contract_address=EXPECTED_CONTRACT_ADDRESS, status="confirming",
        ))
    engine.dispose()


def _target(path: Path):
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return engine


def _target_counts(engine):
    with sessionmaker(bind=engine)() as session:
        return {
            model.__tablename__: session.scalar(
                select(func.count()).select_from(model)
            )
            for model in (
                AnalysisReport, URLAnalysis, TLSAnalysis, ThreatIntelligenceMatch,
                SecurityFinding, ScamAnalysis, BlockchainRecord,
            )
        }


def _target_row(engine, model, identity):
    with sessionmaker(bind=engine)() as session:
        return session.get(model, identity)


def test_source_plan_validates_all_metadata_and_child_models(tmp_path):
    source = tmp_path / "source.db"
    _make_source(source)
    plan = load_source_plan(source)
    assert canonical_report_hash(plan.report) == EXPECTED_REPORT_HASH
    assert {type(row) for row in plan.children} == {
        URLAnalysis, TLSAnalysis, ThreatIntelligenceMatch,
        SecurityFinding, ScamAnalysis, BlockchainRecord,
    }


def test_source_connection_is_read_only(tmp_path):
    source = tmp_path / "source.db"
    _make_source(source)
    engine = _source_engine(source)
    with sessionmaker(bind=engine).begin() as session:
        with pytest.raises(OperationalError):
            session.add(AnalysisReport(
                id=uuid.uuid4(), kind="message", target_hash="a",
                classification="LOW", risk_score=1,
            ))
            session.flush()
    engine.dispose()


def test_dry_run_leaves_target_unchanged_and_apply_is_idempotent(tmp_path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _make_source(source)
    target_engine = _target(target)
    plan = load_source_plan(source)
    before = _target_counts(target_engine)

    inserted, _ = apply_plan(f"sqlite:///{target}", plan, apply=False)
    assert inserted == 7
    assert _target_counts(target_engine) == before

    inserted, _ = apply_plan(f"sqlite:///{target}", plan, apply=True)
    assert inserted == 7
    assert _target_counts(target_engine)["analysis_reports"] == 1
    assert apply_plan(f"sqlite:///{target}", plan, apply=True)[0] == 0
    target_engine.dispose()


@pytest.mark.parametrize("conflict", ["report", "blockchain_report_id", "blockchain_hash", "child"])
def test_any_conflict_aborts_without_changing_existing_rows(tmp_path, conflict):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _make_source(source)
    source_plan = load_source_plan(source)
    target_engine = _target(target)
    factory = sessionmaker(bind=target_engine)
    blockchain = next(row for row in source_plan.children if isinstance(row, BlockchainRecord))
    child = next(row for row in source_plan.children if isinstance(row, URLAnalysis))

    with factory.begin() as session:
        if conflict == "report":
            session.add(AnalysisReport(
                id=REPORT_ID, kind="message", target_hash="different",
                classification="LOW", risk_score=1,
            ))
        elif conflict == "blockchain_report_id":
            session.add(BlockchainRecord(
                id=uuid.uuid4(), report_id=REPORT_ID, report_hash="a" * 64,
                tx_hash="0x" + "1" * 64, chain_id=EXPECTED_CHAIN_ID,
                contract_address=EXPECTED_CONTRACT_ADDRESS, status="failed",
            ))
        elif conflict == "blockchain_hash":
            session.add(BlockchainRecord(
                id=uuid.uuid4(), report_id=uuid.uuid4(),
                report_hash=EXPECTED_REPORT_HASH, tx_hash="0x" + "1" * 64,
                chain_id=EXPECTED_CHAIN_ID, contract_address=EXPECTED_CONTRACT_ADDRESS,
                status="failed",
            ))
        else:
            session.add(URLAnalysis(
                id=child.id, report_id=REPORT_ID, normalized_url="https://different.example",
                domain="different.example", data={"changed": True},
            ))

    before = _target_counts(target_engine)
    with pytest.raises(ImportError):
        apply_plan(f"sqlite:///{target}", source_plan, apply=True)
    assert _target_counts(target_engine) == before
    if conflict == "report":
        assert _target_row(target_engine, AnalysisReport, REPORT_ID).kind == "message"
    target_engine.dispose()
