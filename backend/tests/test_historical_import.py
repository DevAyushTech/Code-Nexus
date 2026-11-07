import sqlite3
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.models import AnalysisReport, BlockchainRecord
from scripts.import_historical_report import (
    EXPECTED_REPORT_HASH,
    EXPECTED_TX_HASH,
    ImportError,
    ImportPlan,
    apply_plan,
    canonical_report_hash,
    load_source_plan,
    preflight_target,
)


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
            id=uuid.UUID("14c7f538-f2d0-4320-865d-15b2d2631704"),
            kind="url",
            target_hash="0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7",
            classification="INCONCLUSIVE",
            risk_score=0,
        )
        session.add(report)
        session.flush()
        session.add(
            BlockchainRecord(
                id=uuid.uuid4(),
                report_id=report.id,
                report_hash=EXPECTED_REPORT_HASH,
                tx_hash=EXPECTED_TX_HASH,
                chain_id=11155111,
                contract_address="0x" + "1" * 40,
                status="confirming",
            )
        )
    engine.dispose()


def test_source_plan_validates_canonical_and_transaction_hash(tmp_path):
    source = tmp_path / "source.db"
    _make_source(source)
    plan = load_source_plan(source)
    assert canonical_report_hash(plan.report) == EXPECTED_REPORT_HASH
    assert any(isinstance(row, BlockchainRecord) for row in plan.children)


def test_dry_run_does_not_insert_and_apply_is_idempotent(tmp_path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _make_source(source)
    Base.metadata.create_all(create_engine(f"sqlite:///{target}"))
    plan = load_source_plan(source)
    target_url = f"sqlite:///{target}"

    inserted, _ = apply_plan(target_url, plan, apply=False)
    assert inserted == 2

    inserted, _ = apply_plan(target_url, plan, apply=True)
    assert inserted == 2
    inserted, _ = apply_plan(target_url, plan, apply=True)
    assert inserted == 0


def test_conflicting_target_aborts_without_overwrite(tmp_path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _make_source(source)
    target_engine = create_engine(f"sqlite:///{target}")
    Base.metadata.create_all(target_engine)
    factory = sessionmaker(bind=target_engine)
    with factory.begin() as session:
        session.add(
            AnalysisReport(
                id=uuid.UUID("14c7f538-f2d0-4320-865d-15b2d2631704"),
                kind="message",
                target_hash="different",
                classification="LOW",
                risk_score=1,
            )
        )
    plan = load_source_plan(source)
    with pytest.raises(ImportError, match="different values"):
        apply_plan(f"sqlite:///{target}", plan, apply=True)
    with factory() as session:
        assert session.get(AnalysisReport, plan.report.id).kind == "message"

