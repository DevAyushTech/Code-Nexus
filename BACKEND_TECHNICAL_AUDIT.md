# Nexus Backend Technical Audit

**Audit date:** 2026-11-07  
**Scope:** `backend/` FastAPI application, services, models, migrations, tests, Docker configuration, and current Sepolia integration.  
**Method:** Source inspection plus the complete backend test suite. No database or blockchain mutation was performed.

## Executive summary

The backend is a functioning MVP with deterministic URL/message analysis, persisted reports, optional provider integrations, TLS/passive inspection, and a deployed Sepolia `ThreatRegistry` integration. The current suite passes **88 tests**.

The main pre-frontend risks are:

1. URL-analysis provider/TLS/website work is synchronous inside request handlers.
2. URL query strings can be persisted and returned through URL analysis.
3. API-key authentication is optional and applies only to three POST submission routes; read routes are public.
4. The health endpoint reports process health only, not database/provider readiness.
5. Blockchain transaction coordination is process-local and does not provide a durable worker/queue model.
6. API response contracts are mostly untyped dictionaries, making frontend versioning harder.

## 1. API inventory

All routes are mounted under `/api/v1` except `/health`.

| Method | Endpoint | Purpose | Request | Response | Auth |
|---|---|---|---|---|---|
| GET | `/health` | Process health | None | `{"status":"ok","service":"..."}` | None |
| POST | `/api/v1/analyze/url` | Analyze a public URL and persist a report | `URLAnalyzeRequest`: `url: HttpUrl` | `AnalysisResponse` | Optional `X-API-Key`; URL rate limit |
| POST | `/api/v1/analyze/message` | Deterministic scam-message analysis plus optional AI | `MessageAnalyzeRequest`: 1–50,000 chars | `AnalysisResponse` | Optional `X-API-Key`; message rate limit |
| GET | `/api/v1/reports/{report_id}` | Retrieve an analysis report | UUID path parameter | `AnalysisResponse` | None |
| GET | `/api/v1/dashboard/summary` | Aggregate report counts by classification | None | `{"total": int, "classifications": object}` | None |
| GET | `/api/v1/threats` | Paginated threat-report feed | `skip >= 0`, `1 <= limit <= 100` | `{"items": [...], "skip": int, "limit": int}` | None |
| POST | `/api/v1/threat-reports` | Create a user threat report | `ThreatReportCreate`: indicator 1–2048 chars, description 1–10,000 chars, fixed report type | `ThreatReportResponse` | Optional `X-API-Key`; threat-report rate limit |
| GET | `/api/v1/threat-reports/{report_id}` | Retrieve a threat report | UUID path parameter | `ThreatReportResponse` | None |
| POST | `/api/v1/blockchain/register` | Register an analysis commitment locally or on Sepolia | `{"report_id": UUID}` | Mode-specific dictionary | None |
| GET | `/api/v1/blockchain/verify/{report_id}` | Independently verify a commitment | UUID path parameter | Mode-specific verification dictionary | None |

### Request validation and errors

- Invalid JSON/schema/path values are FastAPI/Pydantic validation errors, normally HTTP 422.
- URL deterministic validation raises HTTP 400 for invalid/unsafe URLs.
- Missing reports return HTTP 404.
- Optional API-key failures return HTTP 401.
- Rate limits return HTTP 429.
- Blockchain configuration/dependency failures return HTTP 503; RPC/transaction failures return HTTP 502 on registration.
- Unhandled exceptions are logged server-side and returned as generic HTTP 500 JSON:

```json
{"error":{"code":"internal_error","message":"An internal error occurred."}}
```

### Database and external integrations

- URL analysis writes `analysis_reports`, `url_analyses`, `security_findings`, `threat_indicators`, `tls_analyses`, and provider `threat_intelligence_matches`.
- Message analysis writes `analysis_reports`, `scam_analyses`, `security_findings`, and IOC-derived `threat_indicators`.
- Threat reports write `threat_reports`.
- Blockchain routes read/write `blockchain_records`; Sepolia calls Web3.py and the deployed contract.
- URL analysis calls URLhaus, Google Safe Browsing, TLS socket inspection, and passive HTTP inspection.
- Message analysis optionally calls the configured AI provider.

## 2. Feature completeness

| Feature | Classification | Evidence |
|---|---|---|
| URL analysis | IMPLEMENTED_AND_TESTED | `url_analysis.py`, route tests, SSRF tests |
| Message analysis | IMPLEMENTED_AND_TESTED | `message_analysis.py`, API/AI tests |
| Threat reports | IMPLEMENTED_AND_TESTED | CRUD route tests |
| Dashboard summary | IMPLEMENTED_BUT_NOT_FULLY_TESTED | Route exists; limited aggregation tests |
| Threat feed | IMPLEMENTED_BUT_NOT_FULLY_TESTED | `skip`/`limit` route exists; filtering/order/empty-page coverage is limited |
| Analysis retrieval | IMPLEMENTED_AND_TESTED | Report retrieval tests |
| Blockchain registration | IMPLEMENTED_BUT_NOT_FULLY_TESTED | Mock and Web3 unit coverage; live registration path is operationally sensitive |
| Independent blockchain verification | IMPLEMENTED_BUT_NOT_FULLY_TESTED | Web3 verification tests; production retry/concurrency coverage is limited |
| URLhaus | IMPLEMENTED_AND_TESTED | Match, clean, timeout, 429, 5xx, invalid JSON, credential tests |
| Google Safe Browsing | IMPLEMENTED_AND_TESTED | Match, clean, timeout, 429, 5xx, invalid JSON, credential tests |
| TLS inspection | IMPLEMENTED_AND_TESTED | Certificate failure/success and diagnostic tests |
| Passive website inspection | IMPLEMENTED_AND_TESTED | Response-size, redirect, SSRF, and diagnostic tests |
| AI analysis | IMPLEMENTED_BUT_NOT_FULLY_TESTED | Provider parsing/error tests; live provider behavior is not tested |

## 3. Database audit

### Models and constraints

The ORM defines nine application tables. Foreign keys connect child analysis tables and blockchain records to `analysis_reports`. Unique constraints enforce one blockchain record per report and per report hash. Indexes exist on report kinds, hashes, domains, child `report_id` values, threat indicator fields, and threat-report hashes.

### Migration history

The Alembic chain is linear:

```text
20261107_0001 -> 20261107_0002 -> 20261107_0003
```

The verified local database was at revision `20261107_0003`, passed SQLite integrity checks, and retained existing application data. No migration was run during this audit.

### SQLite/PostgreSQL

- SQLite is supported for local Windows development.
- Docker Compose injects PostgreSQL through the internal `db` hostname.
- SQLAlchemy types used are broadly portable, but PostgreSQL should receive an independent migration/integration test before production use.
- SQLite has limited write concurrency; the current synchronous request model and single-process development use are appropriate, but multi-worker SQLite is not a production target.

### Transaction and retention observations

- Analysis persistence commits a report and related rows as one unit and rolls back on commit failure.
- Threat-report creation commits directly without an explicit rollback handler.
- No retention, deletion, archival, or purge policy is implemented.
- Stored URL analysis includes normalized URLs and query-key metadata; provider evidence is sanitized by current provider services.

## 4. Reliability and performance

- HTTP provider calls use the configured request timeout and bounded two-attempt retries.
- URLhaus and Safe Browsing failures are represented as integration statuses and do not block deterministic analysis.
- TLS and passive inspection are synchronous and can consume the request worker for network timeout durations.
- No background task queue exists.
- Threat feed pagination is offset-based and capped at 100; it has no filtering or cursor pagination.
- Response/body limits exist for passive inspection.
- Rate limiting is in-memory and process-local.
- Logging has a generic unhandled-exception handler but no structured request IDs, metrics, tracing, provider latency metrics, or alerting.
- Blockchain registration uses a process-local lock, persists the transaction hash after broadcast, and rechecks persisted hashes. Multi-process nonce coordination and durable job recovery are not implemented.

## 5. Verified test result

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Result:

```text
88 passed, 1 warning
```

The warning is the existing `pytest-asyncio` loop-scope deprecation warning.

