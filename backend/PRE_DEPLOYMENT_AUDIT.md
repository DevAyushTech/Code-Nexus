# Nexus Backend Pre-Deployment Audit

Audit date: 2026-11-08  
Scope: existing backend only. No frontend, database records, smart contract, blockchain transaction, or secret values were modified or exposed.

## Status summary

| Area | Status | Result |
|---|---|---|
| FastAPI production startup/configuration | PASS | `Dockerfile` starts `uvicorn app.main:app` on `0.0.0.0:8000`; protected-demo validation rejects an empty API key; supported SQLite/PostgreSQL URLs are validated. |
| PostgreSQL compatibility/migrations | NOT VERIFIED | Alembic has a linear `20261107_0001` → `20261107_0002` → `20261107_0003` history; existing SQLite is at `20261107_0003` and integrity check is `ok`. No disposable PostgreSQL instance was available. |
| Dockerfile/Compose | NOT VERIFIED | Static checks pass for startup, secret exclusion, PostgreSQL healthcheck, and healthy dependency gating. Docker is unavailable, so no image build or Compose run was performed. |
| Environment variables/secret management | PASS | Compose requires external `POSTGRES_PASSWORD` and `API_AUTH_KEY`; `.env` is ignored and excluded from the image; no secret-like files are tracked. |
| CORS | PASS | Configured `CORS_ORIGINS` is used; `X-API-Key` and JSON headers are allowed; credentials are disabled. The actual deployed frontend origin still requires operator configuration. |
| Authentication/API security | PASS | Protected API routes use `X-API-Key` security metadata and reject missing/invalid keys in protected mode. Rate limiting is bounded but in-process. |
| Health/readiness | PASS | `/health` is liveness-only; `/health/ready` executes `SELECT 1` and returns sanitized `503` on database failure. |
| Sepolia read-only verification | NOT VERIFIED | Verification code is read-only and confirmation-gated, and mocked/read-only tests pass. A live RPC verification was not repeated during this audit; no live claim is made. |
| Logging/error handling/runtime reliability | PASS | Request IDs are returned, unexpected errors are sanitized, and readiness errors do not expose connection details. |
| Git hygiene | PASS | `.env`, `.env.*`, databases, deployment artifacts, virtual environments, and key-like files are ignored; only `.env.example` is tracked among environment files. |

## Automated and read-only checks

- Focused deployment/database/blockchain tests: **51 passed, 1 warning**.
- Complete backend suite: **120 passed, 1 warning**.
- Alembic current revision: **`20261107_0003 (head)`**.
- Existing SQLite `PRAGMA integrity_check`: **`ok`**.
- `git diff --check`: **passed**.
- Docker availability: **not available** (`docker` command not found).
- PostgreSQL integration, Docker build, and Compose execution: **not verified**.
- Live frontend integration: **not performed**.
- Live Sepolia RPC verification: **not repeated in this audit**.

The warning is the existing `pytest-asyncio` loop-scope deprecation warning; it did not fail tests.

## Deployment environment variables

Names only; values must be supplied through the deployment platform or an external secret mechanism.

### Required for protected Docker Compose staging

- `POSTGRES_PASSWORD`
- `API_AUTH_KEY`

### Recommended/required runtime configuration

- `APP_ENV`
- `API_AUTH_MODE`
- `DATABASE_URL`
- `CORS_ORIGINS`

`POSTGRES_DB` and `POSTGRES_USER` are optional in Compose and have defaults, but should be explicitly managed by the deployment environment when required by operational policy.

### Optional provider configuration

- `URLHAUS_API_URL`
- `URLHAUS_AUTH_KEY`
- `GOOGLE_SAFE_BROWSING_URL`
- `GOOGLE_SAFE_BROWSING_KEY`
- `AI_ENABLED`
- `AI_PROVIDER`
- `AI_API_KEY`
- `AI_BASE_URL`
- `AI_MODEL`

### Sepolia read-only verification configuration

- `BLOCKCHAIN_MODE`
- `BLOCKCHAIN_RPC_URL`
- `BLOCKCHAIN_CONTRACT_ADDRESS`
- `BLOCKCHAIN_CHAIN_ID`
- `BLOCKCHAIN_CONFIRMATIONS`
- `BLOCKCHAIN_TX_TIMEOUT`
- `BLOCKCHAIN_GAS_LIMIT`

### Sepolia registration-only configuration

- `BLOCKCHAIN_PRIVATE_KEY`
- `BLOCKCHAIN_ACCOUNT_ADDRESS`

The private key is not needed for read-only verification and must never be placed in frontend configuration. `BLOCKCHAIN_CONTRACT_OWNER` is used by deployment tooling, not by the FastAPI runtime settings.

### Rate-limit/runtime tuning

- `REQUEST_TIMEOUT_SECONDS`
- `MAX_RESPONSE_BYTES`
- `MAX_REDIRECTS`
- `RATE_LIMIT_WINDOW_SECONDS`
- `URL_ANALYSIS_RATE_LIMIT`
- `MESSAGE_ANALYSIS_RATE_LIMIT`
- `THREAT_REPORT_RATE_LIMIT`

## Blockers before deployment

1. Provide external `POSTGRES_PASSWORD` and a non-empty `API_AUTH_KEY`; use `API_AUTH_MODE=protected_demo`.
2. Set `CORS_ORIGINS` to the exact deployed frontend origin(s), not the localhost default.
3. Run `python -m alembic upgrade head` only against the new disposable/staging PostgreSQL database before starting the API. Do not run it against the existing SQLite database unless its migration adoption procedure has been explicitly approved.
4. If blockchain verification is part of the demo, configure Sepolia read-only variables and perform a separate safe live verification before the demo. Do not use the registration endpoint as a health check.
5. If PostgreSQL or Docker execution is a release gate, obtain an isolated Docker/managed PostgreSQL environment and validate them there; they were not available in this audit.

## Staging suitability

**Conditionally suitable for a free single-worker staging deployment** after the configuration blockers above are completed. The backend has safe startup, protected-demo authentication, database readiness, manual migrations, sanitized errors, and static container safeguards.

## Remaining production-readiness limitations

- PostgreSQL compatibility and Docker runtime remain unverified in this environment.
- The rate limiter is process-local and does not coordinate across workers or instances; use one worker for the hackathon demo.
- Authentication is one shared demo/admin API key, not multi-user authentication.
- Live frontend integration was not tested.
- Provider tests are mocked except for previously recorded benign read-only checks; mocked tests do not prove live provider availability.
- Live Sepolia verification was not repeated during this audit.

## Files changed

- `PRE_DEPLOYMENT_AUDIT.md` — added this audit report.

