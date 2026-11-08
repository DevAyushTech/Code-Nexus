from pathlib import Path
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.api.v1 import router
from app.database.session import Base, get_db
from app.main import app
from app.models.models import AnalysisReport, SecurityFinding, ThreatReport


@pytest.fixture
def database_client(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase4.db'}", connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    yield TestClient(app), session_factory
    app.dependency_overrides.clear()
    engine.dispose()


def test_empty_dashboard_and_feed_are_consistent(database_client):
    client, _ = database_client
    assert client.get("/api/v1/dashboard/summary").json() == {
        "total": 0,
        "total_reports": 0,
        "classifications": {},
    }
    assert client.get("/api/v1/threats?skip=0&limit=10").json() == {"items": [], "skip": 0, "limit": 10}


def test_threat_feed_filters_and_paginates(database_client):
    client, session_factory = database_client
    for report_type in ("url", "message", "url"):
        response = client.post(
            "/api/v1/threat-reports",
            json={"indicator": f"https://example.com/{report_type}", "report_type": report_type, "description": report_type},
        )
        assert response.status_code == 201
    filtered = client.get("/api/v1/threats?report_type=url&skip=1&limit=1")
    assert filtered.status_code == 200
    assert filtered.json()["skip"] == 1
    assert filtered.json()["limit"] == 1
    assert len(filtered.json()["items"]) == 1
    assert filtered.json()["items"][0]["report_type"] == "url"
    assert client.get("/api/v1/threats?report_type=invalid").status_code == 422


def test_foreign_key_integrity_rejects_orphan_rows(database_client):
    _, session_factory = database_client
    with session_factory() as db:
        db.add(AnalysisReport(kind="message", target_hash="a" * 64, classification="LOW", risk_score=1))
        db.commit()
        db.add(SecurityFinding(
            report_id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
            name="orphan",
            severity="low",
            evidence="test",
            source="test",
            explanation="test",
            recommendation="test",
        ))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_threat_report_write_rolls_back_on_database_error(monkeypatch):
    class FailingSession:
        rolled_back = False

        def add(self, item):
            pass

        def commit(self):
            from sqlalchemy.exc import OperationalError
            raise OperationalError("INSERT", {}, RuntimeError("test database failure"))

        def rollback(self):
            self.rolled_back = True

    failing = FailingSession()

    def override_db():
        yield failing

    app.dependency_overrides[get_db] = override_db
    try:
        response = TestClient(app).post(
            "/api/v1/threat-reports",
            json={"indicator": "https://example.com", "report_type": "url", "description": "test"},
        )
        assert response.status_code == 503
        assert failing.rolled_back is True
    finally:
        app.dependency_overrides.clear()


def test_fresh_alembic_upgrade_uses_disposable_sqlite(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'fresh.db'}"
    environment = dict(__import__("os").environ)
    environment["DATABASE_URL"] = database_url
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
