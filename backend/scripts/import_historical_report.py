"""Safely import the preserved historical report into a new database.

The command is dry-run by default. It never submits blockchain transactions.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.models import (
    AnalysisReport,
    BlockchainRecord,
    ScamAnalysis,
    SecurityFinding,
    TLSAnalysis,
    ThreatIntelligenceMatch,
    URLAnalysis,
)

REPORT_ID = uuid.UUID("14c7f538-f2d0-4320-865d-15b2d2631704")
EXPECTED_REPORT_HASH = "215bc8bd660bc72af22e6e7b595479f291058d8b3b1c8a93856500d8f956effb"
EXPECTED_TX_HASH = "0x9ceb8cd0e08c082ab0ee639aab5c6f4cdb39c035aa9340328be3e15912e9789f"
CHILD_MODELS = (
    URLAnalysis,
    TLSAnalysis,
    ThreatIntelligenceMatch,
    SecurityFinding,
    ScamAnalysis,
    BlockchainRecord,
)


class ImportError(RuntimeError):
    """Raised when the source or target cannot be safely imported."""


@dataclass(frozen=True)
class ImportPlan:
    report: AnalysisReport
    children: tuple[Any, ...]


def canonical_report_hash(report: AnalysisReport) -> str:
    value = f"{report.id}:{report.target_hash}:{report.classification}:{report.risk_score}"
    return hashlib.sha256(value.encode()).hexdigest()


def _read_only_source_engine(source: Path):
    resolved = source.resolve()
    if not resolved.is_file():
        raise ImportError("Source SQLite database was not found.")
    uri = f"file:{resolved.as_posix()}?mode=ro"
    return create_engine("sqlite+pysqlite://", creator=lambda: sqlite3.connect(uri, uri=True))


def _column_values(row: Any) -> dict[str, Any]:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def _same_value(left: Any, right: Any) -> bool:
    if isinstance(left, uuid.UUID) or isinstance(right, uuid.UUID):
        return str(left) == str(right)
    return left == right


def _same_row(source: Any, target: Any) -> bool:
    source_values = _column_values(source)
    target_values = _column_values(target)
    return source_values.keys() == target_values.keys() and all(
        _same_value(source_values[name], target_values[name]) for name in source_values
    )


def load_source_plan(source: Path) -> ImportPlan:
    engine = _read_only_source_engine(source)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with session_factory() as session:
            report = session.get(AnalysisReport, REPORT_ID)
            if report is None:
                raise ImportError("Historical analysis report was not found in the source database.")
            blockchain = session.scalar(
                select(BlockchainRecord).where(BlockchainRecord.report_id == REPORT_ID)
            )
            if blockchain is None:
                raise ImportError("Historical blockchain record was not found in the source database.")
            actual_hash = canonical_report_hash(report)
            if actual_hash != EXPECTED_REPORT_HASH:
                raise ImportError("Source report canonical hash does not match the expected historical hash.")
            if blockchain.report_hash != EXPECTED_REPORT_HASH:
                raise ImportError("Source blockchain report hash does not match the expected historical hash.")
            if blockchain.tx_hash != EXPECTED_TX_HASH:
                raise ImportError("Source transaction hash does not match the expected historical transaction.")

            children: list[Any] = []
            for model in CHILD_MODELS:
                rows = session.scalars(
                    select(model).where(model.report_id == REPORT_ID)
                ).all()
                children.extend(rows)
            return ImportPlan(report=report, children=tuple(children))
    finally:
        engine.dispose()


def _existing_by_primary_key(session: Session, row: Any) -> Any | None:
    identity = {column.name: getattr(row, column.name) for column in row.__table__.primary_key.columns}
    return session.get(type(row), identity if len(identity) > 1 else next(iter(identity.values())))


def _check_unique_blockchain_conflicts(session: Session, row: BlockchainRecord) -> None:
    for field in ("report_id", "report_hash"):
        existing = session.scalar(
            select(BlockchainRecord).where(getattr(BlockchainRecord, field) == getattr(row, field))
        )
        if existing is not None and existing.id != row.id and not _same_row(existing, row):
            raise ImportError(f"Target blockchain record conflicts on unique field {field}.")


def preflight_target(session: Session, plan: ImportPlan) -> list[Any]:
    rows = [plan.report, *plan.children]
    conflicts: list[Any] = []
    for source_row in rows:
        target_row = _existing_by_primary_key(session, source_row)
        if target_row is not None and not _same_row(source_row, target_row):
            conflicts.append(source_row)
    blockchain = next(row for row in plan.children if isinstance(row, BlockchainRecord))
    _check_unique_blockchain_conflicts(session, blockchain)
    if conflicts:
        raise ImportError("Target contains existing records with different values; no writes were performed.")
    return [row for row in rows if _existing_by_primary_key(session, row) is None]


def apply_plan(target_url: str, plan: ImportPlan, apply: bool) -> tuple[int, int]:
    engine = create_engine(target_url, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with session_factory.begin() as session:
            to_insert = preflight_target(session, plan)
            if apply:
                for source_row in to_insert:
                    session.add(type(source_row)(**_column_values(source_row)))
            return len(to_insert), len(plan.report.__table__.columns) + sum(
                len(row.__table__.columns) for row in plan.children
            )
    except Exception:
        if apply:
            raise
        raise
    finally:
        engine.dispose()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "nexus.db",
        help="Read-only source SQLite path.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit the idempotent import. Omit for a dry-run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_url = os.environ.get("DATABASE_URL")
    if not target_url:
        print("DATABASE_URL must be supplied at execution time.", file=sys.stderr)
        return 2
    if not target_url.startswith(("postgresql://", "postgresql+psycopg://")):
        print("DATABASE_URL must be a PostgreSQL SQLAlchemy URL for this import.", file=sys.stderr)
        return 2
    try:
        plan = load_source_plan(args.source)
        inserted, _ = apply_plan(target_url, plan, args.apply)
    except ImportError as exc:
        print(f"Import aborted: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("Import aborted due to a database error; no changes were committed.", file=sys.stderr)
        return 1
    action = "would be inserted" if not args.apply else "inserted"
    print(f"Historical report preflight passed; {inserted} record(s) {action}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
