from pathlib import Path
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.v1 import router
from app.core.config import settings
from app.core.security import jwks_cache, limiter
from app.database.session import Base, get_db
from app.main import app
from app.models.models import AnalysisReport, BlockchainRecord, ScamAnalysis, SecurityFinding, ThreatIndicator, ThreatIntelligenceMatch, TLSAnalysis, URLAnalysis
from app.services import website
from app.services.blockchain import BlockchainRPCError, RegistrationResult, VerificationResult
from app.services.ssrf import UnsafeURL, resolve_public_url
from app.services.threat_intel import check_urlhaus


@pytest.fixture
def jwt_credentials(monkeypatch: pytest.MonkeyPatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    kid = "test-kid"
    jwks = {
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": jwt.utils.base64url_encode(numbers.x.to_bytes(32, "big")).decode(),
            "y": jwt.utils.base64url_encode(numbers.y.to_bytes(32, "big")).decode(),
            "use": "sig",
            "kid": kid,
            "alg": "ES256",
        }]
    }

    def fake_get(url: str, timeout: float):
        assert url == settings.supabase_jwks_url
        return httpx.Response(200, request=httpx.Request("GET", url), json=jwks)

    import httpx

    monkeypatch.setattr("app.core.security.httpx.get", fake_get)
    jwks_cache._keys.clear()

    def make_token(**claims):
        payload = {
            "sub": "user-123",
            "aud": settings.supabase_jwt_audience,
            "iss": settings.supabase_jwt_issuer,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            **claims,
        }
        return jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": kid})

    return make_token, jwks


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "api_auth_mode", "demo")
    monkeypatch.setattr(settings, "api_auth_key", None)
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(router, "check_urlhaus", lambda url: {"source": "URLhaus", "status": "completed", "match": False})
    monkeypatch.setattr(router, "inspect_tls", lambda host: {"status": "valid", "expires_at": None})
    monkeypatch.setattr(router, "inspect_website", lambda url: {"source": "passive_website_inspection", "status": "completed"})
    yield TestClient(app), session_factory
    app.dependency_overrides.clear()
    engine.dispose()


def test_url_and_message_reports_persist(client):
    test_client, session_factory = client
    url_response = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com/login"})
    message_response = test_client.post("/api/v1/analyze/message", json={"content": "Urgent payment request: send your OTP."})
    assert url_response.status_code == 201
    assert message_response.status_code == 201
    with session_factory() as db:
        assert db.scalar(select(AnalysisReport).where(AnalysisReport.kind == "url"))
        assert db.scalar(select(URLAnalysis))
        assert db.scalar(select(TLSAnalysis))
        assert db.scalar(select(ThreatIntelligenceMatch))
        assert db.scalar(select(SecurityFinding))
        assert db.scalar(select(ScamAnalysis))
        assert db.scalar(select(ThreatIndicator))


def test_report_can_be_retrieved(client):
    test_client, _ = client
    created = test_client.post("/api/v1/analyze/message", json={"content": "Please verify your password."})
    fetched = test_client.get(f"/api/v1/reports/{created.json()['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["target"] == "[message redacted]"


def test_url_report_retrieval_preserves_safe_integrations_and_evidence_groups(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(router, "check_urlhaus", lambda url: {"source": "URLhaus", "status": "completed", "match": True, "evidence": {"threat": "malware"}})
    monkeypatch.setattr(router, "check_safe_browsing", lambda url: {"source": "Google Safe Browsing", "status": "unavailable", "match": False, "error": "timeout"})
    created = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com/login?token=private-value"})
    assert created.status_code == 201
    report_id = created.json()["id"]
    fetched = test_client.get(f"/api/v1/reports/{report_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert any(item["source"] == "passive_website_inspection" for item in body["integrations"])
    assert len(body["evidence_summary"]["confirmed_matches"]) == 1
    assert len(body["evidence_summary"]["inconclusive_or_unavailable"]) == 1
    assert "private-value" not in str(body)


def test_message_report_does_not_persist_url_query_values(client):
    test_client, session_factory = client
    response = test_client.post("/api/v1/analyze/message", json={"content": "Open https://example.com/login?token=private-value"})
    assert response.status_code == 201
    with session_factory() as db:
        scam = db.scalar(select(ScamAnalysis))
        assert scam is not None
        assert "private-value" not in str(scam.data)


def test_provider_unavailability_is_not_a_clean_verdict(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(router, "check_urlhaus", lambda url: {"source": "URLhaus", "status": "unavailable", "match": False, "error": "timeout"})
    monkeypatch.setattr(router, "check_safe_browsing", lambda url: {"source": "Google Safe Browsing", "status": "not_configured", "match": False})
    response = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 201
    body = response.json()
    assert body["classification"] == "INCONCLUSIVE"
    assert len(body["evidence_summary"]["inconclusive_or_unavailable"]) == 2


def test_one_provider_match_controls_confirmed_classification(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(router, "check_urlhaus", lambda url: {"source": "URLhaus", "status": "completed", "match": True, "confidence": 1.0})
    monkeypatch.setattr(router, "check_safe_browsing", lambda url: {"source": "Google Safe Browsing", "status": "unavailable", "match": False})
    response = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 201
    assert response.json()["classification"] == "CONFIRMED_MALICIOUS"


def test_new_url_reports_redact_query_values(client):
    test_client, session_factory = client
    response = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com/login?token=private-value"})
    assert response.status_code == 201
    assert "private-value" not in response.json()["target"]
    with session_factory() as db:
        stored = db.scalar(select(URLAnalysis))
        assert stored is not None
        assert stored.normalized_url == "https://example.com/login"


def test_sensitive_read_routes_use_demo_api_key(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", SecretStr("test-key"))
    assert test_client.get("/api/v1/dashboard/summary").status_code == 401
    assert test_client.get("/api/v1/threats").status_code == 401
    assert test_client.get("/api/v1/dashboard/summary", headers={"X-API-Key": "test-key"}).status_code == 200


def test_readiness_reports_database_status(client):
    test_client, _ = client
    response = test_client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}


def test_blockchain_status_and_errors_are_safe(client, monkeypatch):
    test_client, session_factory = client
    analysis = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    report_id = uuid.UUID(analysis.json()["id"])
    with session_factory() as db:
        db.add(BlockchainRecord(
            report_id=report_id,
            report_hash="f" * 64,
            tx_hash="0x" + "1" * 64,
            status="submitted",
            chain_id=11155111,
            contract_address="0x" + "2" * 40,
        ))
        db.commit()

    monkeypatch.setattr(router, "get_blockchain_service", lambda: SimpleNamespace(
        config=SimpleNamespace(blockchain_mode="sepolia"),
        adapter=SimpleNamespace(inspect_transaction=lambda tx_hash, submitted_at: RegistrationResult(
            "reverted", tx_hash, 11155111, "0x" + "2" * 40, block_number=12, error_code="transaction_reverted",
        )),
    ))
    response = test_client.post("/api/v1/blockchain/register", json={"report_id": str(report_id)})
    assert response.status_code == 200
    assert response.json()["on_chain"] is False
    with session_factory() as db:
        record = db.scalar(select(BlockchainRecord))
        assert record is not None
        assert record.error_message == "Blockchain transaction was reverted."

    monkeypatch.setattr(router, "get_blockchain_service", lambda: SimpleNamespace(
        config=SimpleNamespace(blockchain_mode="sepolia", blockchain_chain_id=11155111, blockchain_contract_address="0x" + "2" * 40),
        adapter=SimpleNamespace(register_hash=lambda digest, on_submitted: (_ for _ in ()).throw(BlockchainRPCError("private RPC detail"))),
    ))
    fresh_analysis = test_client.post("/api/v1/analyze/message", json={"content": "another"})
    failed = test_client.post("/api/v1/blockchain/register", json={"report_id": fresh_analysis.json()["id"]})
    assert failed.status_code == 502
    assert failed.json()["detail"] == "Blockchain network is unavailable."


def test_threat_report_and_blockchain_commitment_persist(client):
    test_client, session_factory = client
    analysis = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    report = test_client.post("/api/v1/threat-reports", json={"indicator": "https://example.com", "report_type": "url", "description": "test"})
    commitment = test_client.post("/api/v1/blockchain/register", json={"report_id": analysis.json()["id"]})
    verification = test_client.get(f"/api/v1/blockchain/verify/{analysis.json()['id']}")
    assert report.status_code == 201
    assert commitment.json()["status"] == "mock"
    assert verification.json()["verified"] is False
    with session_factory() as db:
        assert db.scalar(select(BlockchainRecord))


def test_sepolia_verification_rejects_stale_local_commitment(client, monkeypatch):
    test_client, session_factory = client
    analysis = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    report_id = uuid.UUID(analysis.json()["id"])
    with session_factory() as db:
        db.add(BlockchainRecord(
            report_id=report_id,
            report_hash="f" * 64,
            status="confirmed",
            chain_id=11155111,
            contract_address="0x" + "1" * 40,
        ))
        db.commit()

    adapter = SimpleNamespace(verify_commitment=lambda expected_hash, tx_hash: VerificationResult(
        "verified", True, 11155111, "0x" + "1" * 40, True, "0x" + "2" * 40, 123, 3, 1, 10
    ))
    monkeypatch.setattr(router, "get_blockchain_service", lambda: SimpleNamespace(
        config=SimpleNamespace(blockchain_mode="sepolia"),
        adapter=adapter,
    ))
    response = test_client.get(f"/api/v1/blockchain/verify/{report_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "mismatch"
    assert response.json()["verified"] is False


def test_verification_on_chain_requires_verified_commitment(client, monkeypatch):
    test_client, _ = client
    analysis = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    report_id = uuid.UUID(analysis.json()["id"])
    monkeypatch.setattr(router, "get_blockchain_service", lambda: SimpleNamespace(
        config=SimpleNamespace(blockchain_mode="sepolia"),
        adapter=SimpleNamespace(verify_commitment=lambda expected_hash, tx_hash: VerificationResult(
            "confirming", False, 11155111, "0x" + "1" * 40, True, "0x" + "2" * 40, 123, 1, 1, 10, "insufficient_confirmations"
        )),
    ))
    response = test_client.get(f"/api/v1/blockchain/verify/{report_id}")
    assert response.status_code == 200
    assert response.json()["on_chain"] is False
    assert response.json()["status"] == "confirming"


def test_rate_limit_returns_429(client, monkeypatch):
    test_client, _ = client
    limiter._events.clear()
    monkeypatch.setattr(settings, "message_analysis_rate_limit", 1)
    first = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    second = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    assert first.status_code == 201
    assert second.status_code == 429


def test_redirect_to_private_is_rejected(monkeypatch):
    class RedirectResponse:
        status = 302
        def getheader(self, name):
            return "http://127.0.0.1/private"
        def close(self):
            pass

    class Connection:
        def close(self):
            pass

    monkeypatch.setattr(website, "open_pinned_response", lambda url, timeout: (_ for _ in ()).throw(UnsafeURL("private redirect")))
    result = website.inspect_website("https://example.com")
    assert result["status"] == "unavailable"


def test_oversized_response_stops_without_response_content(monkeypatch):
    class Response:
        status = 200
        def getheaders(self):
            return []
        def read(self, size):
            return b"x" * size
        def close(self):
            pass

    class Connection:
        def close(self):
            pass

    monkeypatch.setattr(website.settings, "max_response_bytes", 10)
    monkeypatch.setattr(website, "open_pinned_response", lambda url, timeout: (SimpleNamespace(address="203.0.113.1"), Response(), Connection()))
    result = website.inspect_website("https://example.com")
    assert result["status"] == "unavailable"
    assert result["error"] == "UnsafeURL"


def test_dns_resolution_must_be_public(monkeypatch):
    monkeypatch.setattr("app.services.ssrf.socket.getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.1", 443))])
    with pytest.raises(UnsafeURL):
        resolve_public_url("https://rebind.example")


def test_pinned_resolution_is_the_socket_destination(monkeypatch):
    seen = []
    monkeypatch.setattr("app.services.ssrf.socket.getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))])
    monkeypatch.setattr("app.services.ssrf.socket.create_connection", lambda address, timeout: seen.append(address) or (_ for _ in ()).throw(OSError("stop")))
    with pytest.raises(OSError):
        from app.services.ssrf import open_pinned_response
        open_pinned_response("https://example.com", 1)
    assert seen == [("93.184.216.34", 443)]


def test_authenticated_routes_require_api_key(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", SecretStr("test-key"))
    response = test_client.post("/api/v1/analyze/message", json={"content": "hello"})
    assert response.status_code == 401
    response = test_client.post("/api/v1/analyze/message", headers={"X-API-Key": "wrong-key"}, json={"content": "hello"})
    assert response.status_code == 401
    response = test_client.post("/api/v1/analyze/message", headers={"X-API-Key": "test-key"}, json={"content": "hello"})
    assert response.status_code == 201


def test_valid_supabase_jwt_authenticates_protected_route(client, jwt_credentials, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", None)
    make_token, _ = jwt_credentials
    response = test_client.post(
        "/api/v1/analyze/message",
        headers={"Authorization": f"Bearer {make_token()}"},
        json={"content": "hello"},
    )
    assert response.status_code == 201


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://wrong.example/auth/v1"},
        {"aud": "wrong-audience"},
        {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
    ],
)
def test_invalid_supabase_jwt_claims_are_rejected(client, jwt_credentials, monkeypatch, claims):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", None)
    make_token, _ = jwt_credentials
    response = test_client.post(
        "/api/v1/analyze/message",
        headers={"Authorization": f"Bearer {make_token(**claims)}"},
        json={"content": "hello"},
    )
    assert response.status_code == 401


def test_invalid_signature_unsupported_algorithm_unknown_kid_and_malformed_token_are_rejected(
    client, jwt_credentials, monkeypatch
):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", None)
    make_token, _ = jwt_credentials
    invalid_signature = make_token()[:-1] + ("a" if make_token()[-1] != "a" else "b")
    unsupported_algorithm = jwt.encode(
        {"iss": settings.supabase_jwt_issuer, "aud": settings.supabase_jwt_audience, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "secret",
        algorithm="HS256",
        headers={"kid": "test-kid"},
    )
    unknown_kid = make_token()
    unknown_kid = jwt.encode(
        jwt.decode(unknown_kid, options={"verify_signature": False}),
        ec.generate_private_key(ec.SECP256R1()),
        algorithm="ES256",
        headers={"kid": "unknown-kid"},
    )
    for token in (invalid_signature, unsupported_algorithm, unknown_kid, "not-a-jwt"):
        response = test_client.post(
            "/api/v1/analyze/message",
            headers={"Authorization": f"Bearer {token}"},
            json={"content": "hello"},
        )
        assert response.status_code == 401


def test_invalid_bearer_does_not_fall_back_to_api_key(client, jwt_credentials, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", SecretStr("test-key"))
    response = test_client.post(
        "/api/v1/analyze/message",
        headers={"Authorization": "Bearer malformed", "X-API-Key": "test-key"},
        json={"content": "hello"},
    )
    assert response.status_code == 401


def test_all_protected_routes_accept_valid_supabase_jwt(client, jwt_credentials, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", None)
    make_token, _ = jwt_credentials
    headers = {"Authorization": f"Bearer {make_token()}"}
    created = test_client.post("/api/v1/analyze/message", headers=headers, json={"content": "hello"})
    report_id = created.json()["id"]
    threat = test_client.post(
        "/api/v1/threat-reports",
        headers=headers,
        json={"indicator": "example.com", "report_type": "domain", "description": "test"},
    )
    for response in (
        test_client.get(f"/api/v1/reports/{report_id}", headers=headers),
        test_client.get("/api/v1/dashboard/summary", headers=headers),
        test_client.get("/api/v1/threats", headers=headers),
        test_client.get(f"/api/v1/threat-reports/{threat.json()['id']}", headers=headers),
        test_client.post("/api/v1/blockchain/register", headers=headers, json={"report_id": report_id}),
        test_client.get(f"/api/v1/blockchain/verify/{report_id}", headers=headers),
    ):
        assert response.status_code != 401


def test_jwks_cache_refreshes_for_unknown_kid(client, jwt_credentials, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(settings, "api_auth_key", None)
    make_token, jwks = jwt_credentials
    first = test_client.post(
        "/api/v1/analyze/message",
        headers={"Authorization": f"Bearer {make_token()}"},
        json={"content": "hello"},
    )
    assert first.status_code == 201
    assert len(jwks_cache._keys) == 1


def test_cors_allows_configured_frontend_and_rejects_other_origins(client):
    test_client, _ = client
    allowed = test_client.options("/api/v1/dashboard/summary", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"})
    api_key_allowed = test_client.options(
        "/api/v1/dashboard/summary",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )
    denied = test_client.options("/api/v1/dashboard/summary", headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "GET"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "x-api-key" in api_key_allowed.headers.get("access-control-allow-headers", "").lower()
    authorization_allowed = test_client.options(
        "/api/v1/dashboard/summary",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert authorization_allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert denied.headers.get("access-control-allow-origin") is None


def test_openapi_declares_api_key_security_for_protected_routes():
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["APIKeyHeader"]["name"] == "X-API-Key"
    assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    protected_paths = (
        "/api/v1/analyze/url",
        "/api/v1/analyze/message",
        "/api/v1/reports/{report_id}",
        "/api/v1/dashboard/summary",
        "/api/v1/threats",
        "/api/v1/threat-reports",
        "/api/v1/threat-reports/{report_id}",
        "/api/v1/blockchain/register",
        "/api/v1/blockchain/verify/{report_id}",
    )
    for path in protected_paths:
        operations = schema["paths"][path]
        for operation in operations.values():
            if isinstance(operation, dict) and "responses" in operation:
                assert {"APIKeyHeader": []} in operation["security"]
                assert {"HTTPBearer": []} in operation["security"]


def test_typed_blockchain_response_schemas_are_in_openapi():
    schemas = app.openapi()["components"]["schemas"]
    assert "BlockchainRegistrationResponse" in schemas
    assert "BlockchainVerificationResponse" in schemas


def test_urlhaus_requires_validated_evidence(monkeypatch):
    class Response:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"query_status": "ok", "url": "https://other.example/", "threat": "malware", "url_status": "online"}

    monkeypatch.setattr("app.services.threat_intel.settings.urlhaus_auth_key", SecretStr("secret"))
    monkeypatch.setattr("app.services.threat_intel.httpx.post", lambda *args, **kwargs: Response())
    result = check_urlhaus("https://example.com/")
    assert result["status"] == "completed"
    assert result["match"] is False


def test_url_analysis_completes_when_provider_is_unavailable(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(router, "check_urlhaus", lambda url: {"source": "URLhaus", "status": "unavailable", "match": False})
    monkeypatch.setattr(router, "check_safe_browsing", lambda url: {"source": "Google Safe Browsing", "status": "completed", "match": False})

    response = test_client.post("/api/v1/analyze/url", json={"url": "https://example.com"})

    assert response.status_code == 201
    integrations = {item["source"]: item for item in response.json()["integrations"]}
    assert integrations["URLhaus"]["status"] == "unavailable"
    assert integrations["Google Safe Browsing"]["status"] == "completed"
