from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main
from app.core.config import Settings


def test_database_url_rejects_empty_and_unsupported_values():
    with pytest.raises(ValidationError, match="DATABASE_URL"):
        Settings(database_url="")
    with pytest.raises(ValidationError, match="SQLite or PostgreSQL"):
        Settings(database_url="mysql://localhost/nexus")


def test_health_includes_request_id():
    response = TestClient(main.app).get("/health")
    assert response.status_code == 200
    assert response.headers["X-Request-ID"]
    assert response.json()["status"] == "ok"


def test_readiness_returns_sanitized_database_error(monkeypatch):
    class BrokenEngine:
        def connect(self):
            raise RuntimeError("postgresql://user:password@db:5432/nexus")

    monkeypatch.setattr(main, "engine", BrokenEngine())
    response = TestClient(main.app).get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable."}
    assert "password" not in response.text
    assert response.headers["X-Request-ID"]


def test_docker_runtime_files_are_safe():
    root = Path(__file__).parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'CMD ["uvicorn", "app.main:app"' in dockerfile
    assert "COPY alembic alembic" in dockerfile
    assert ".env" in dockerignore
    assert "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?" in compose
    assert "healthcheck:" in compose
    assert "condition: service_healthy" in compose
    assert "API_AUTH_KEY: ${API_AUTH_KEY:?" in compose
    assert "password: nexus" not in compose.lower()
