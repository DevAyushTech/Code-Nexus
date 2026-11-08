# Nexus Hackathon MVP Readiness Report

**Audit date:** 2026-11-07  
**Scope:** Read-only MVP handover audit. No application code, database, migrations, `.env`, smart contracts, or blockchain state were modified.

## Executive result

**NOT READY for an authenticated frontend demo until `API_AUTH_KEY` is configured.**

The application code and tests support the single-admin API-key model, CORS supports `X-API-Key`, the local database is healthy, all six historical reports are readable, and the existing registered Sepolia report verifies successfully without a transaction. The current `.env` has `API_AUTH_KEY` empty, so protected routes are fail-open by design. OpenAPI also does not currently declare an API-key security scheme.

## Verification matrix

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Protected endpoints reject requests without a valid API key | **FAIL** | Current `.env` reports `API_AUTH_KEY=EMPTY`; read-only smoke calls returned `201`/`200`/`404`, not `401`. The guard is conditional in [security.py:29-55](D:/DevProjects/Nexus/backend/app/core/security.py). Focused behavior is covered by [test_security_and_api.py:80-86](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py) and [test_security_and_api.py:238-245](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py). |
| 2 | Requests with a valid `X-API-Key` work correctly | **NOT VERIFIED** live across every endpoint | Valid-key behavior is verified in mocked/isolated tests: [test_security_and_api.py:80-86](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py) and [test_security_and_api.py:238-245](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py). A live all-endpoint check was not performed because the configured key is empty and mutation endpoints must not be exercised during this audit. |
| 3 | CORS supports the configured frontend origin and `X-API-Key` | **PASS** | Read-only preflight returned `ORIGIN_ALLOWED=True` and `API_KEY_ALLOWED=True`. Implementation: [main.py:14-22](D:/DevProjects/Nexus/backend/app/main.py). Regression coverage: [test_security_and_api.py:247-260](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py). |
| 4 | `/health` and `/health/ready` behave correctly | **PASS** | Read-only calls returned HTTP 200 with `status=ok` and `status=ready`; database readiness executed `SELECT 1`. Implementation: [main.py:25-39](D:/DevProjects/Nexus/backend/app/main.py). Test: [test_security_and_api.py:88-92](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py). |
| 5 | Dashboard, threat feed, analysis, and report structures match the integration guide | **FAIL** | Typed schemas exist for analysis, dashboard, and feed in [api.py:18-54](D:/DevProjects/Nexus/backend/app/schemas/api.py), and dashboard now returns both `total` and `total_reports` in [router.py:119-123](D:/DevProjects/Nexus/backend/app/api/v1/router.py). However, the guide still says that GET routes do not require authentication and its CORS section omits `X-API-Key`: [FRONTEND_INTEGRATION_GUIDE.md:10-27](D:/DevProjects/Nexus/FRONTEND_INTEGRATION_GUIDE.md), [FRONTEND_INTEGRATION_GUIDE.md:154-157](D:/DevProjects/Nexus/FRONTEND_INTEGRATION_GUIDE.md). |
| 6 | URL query values are redacted for newly generated reports | **PASS** | New URL persistence strips query values in [router.py:52-59](D:/DevProjects/Nexus/backend/app/api/v1/router.py). Focused test: [test_security_and_api.py:69-78](D:/DevProjects/Nexus/backend/tests/test_security_and_api.py). Historical records were not modified. |
| 7 | Historical reports remain readable and blockchain hashes remain unchanged | **PASS** | Read-only check found 6 reports and all 6 returned HTTP 200. Database integrity was `ok`; 1 blockchain record was present and 0 canonical hash mismatches were found. Hash calculation remains [router.py:43-44](D:/DevProjects/Nexus/backend/app/api/v1/router.py). |
| 8 | Existing registered report verifies without submitting a transaction | **PASS** | Read-only Sepolia verification returned HTTP 200, `status=verified`, `verified=True`, and a transaction hash was present. Verification route: [router.py:271-319](D:/DevProjects/Nexus/backend/app/api/v1/router.py). No registration or broadcast endpoint was called. |
| 9 | OpenAPI describes authentication and response schemas correctly | **FAIL** | OpenAPI includes `AnalysisResponse`, `DashboardSummaryResponse`, and `ThreatFeedResponse`, but the read-only schema check found no `securitySchemes`. API-key dependencies are not represented as an OpenAPI authentication requirement. The typed schemas are in [api.py:18-54](D:/DevProjects/Nexus/backend/app/schemas/api.py). |
| 10 | Required environment configuration is present without exposing values | **FAIL** | `DATABASE_URL`, CORS, Sepolia mode/chain/RPC/address/account/private-key/confirmation variable names were present. `API_AUTH_KEY` was present but empty. No values were printed. Configuration definitions: [config.py:8-42](D:/DevProjects/Nexus/backend/app/core/config.py). |

## Endpoint protection status

Sensitive routes intended for the demo:

- `POST /api/v1/analyze/url`
- `POST /api/v1/analyze/message`
- `GET /api/v1/reports/{report_id}`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/threats`
- `POST /api/v1/threat-reports`
- `GET /api/v1/threat-reports/{report_id}`
- `POST /api/v1/blockchain/register`
- `GET /api/v1/blockchain/verify/{report_id}`

All are wired to the shared API-key guard or the rate-limit/API-key guards. However, the guard intentionally returns without authentication when `settings.api_auth_key` is empty. This is acceptable for local development but is a **demo blocker**.

## Response contract findings

- Analysis responses include `id`, `kind`, `target`, `classification`, `risk_score`, `findings`, `integrations`, `evidence_quality`, and optional `ai_analysis`.
- New URL report targets and stored normalized URLs exclude query strings.
- Dashboard implementation returns `total`, `total_reports`, and `classifications`.
- Threat feed is typed as `items`, `skip`, and `limit`.
- Report retrieval now includes integrations and evidence quality.
- Blockchain response dictionaries remain mode/status-dependent and are not represented by dedicated Pydantic response models.
- The integration guide contains stale statements saying GET and blockchain routes are unauthenticated and omits `X-API-Key` from its CORS description. This must be corrected before frontend handover.

## Test results

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Result:

```text
92 passed, 1 warning
```

The warning is the existing `pytest-asyncio` loop-scope deprecation warning. No tests were disabled or weakened.

Focused remediation coverage includes:

- API-key rejection and acceptance.
- URL query redaction.
- Database readiness.
- CORS `X-API-Key` preflight.
- Blockchain status/error sanitization.
- Existing SSRF, TLS, provider, and blockchain unit coverage.

## Remaining blockers

1. **Configure a non-empty strong demo/admin `API_AUTH_KEY`** in the deployment environment. Do not commit it or print it.
2. **Update the frontend integration guide** so its authentication and CORS sections match the current guarded routes.
3. **Add an OpenAPI API-key security scheme** or explicitly document the header outside the generated schema. Without this, generated frontend clients will not know that `X-API-Key` is required.
4. Do not expose the API directly to judges until the key is configured and tested from the frontend.

## Frontend developer handover checklist

- [ ] Use the configured API base URL.
- [ ] Send `X-API-Key` on every sensitive route listed above.
- [ ] Confirm the frontend origin is included in `CORS_ORIGINS`.
- [ ] Handle HTTP 401, 404, 422, 429, 502, and 503.
- [ ] Treat `INCONCLUSIVE`, `unavailable`, `not_configured`, `error`, and `rate_limited` as non-clean outcomes.
- [ ] Render URL targets as untrusted text; query values are redacted for new reports.
- [ ] Handle provider integration statuses independently.
- [ ] Display blockchain states including `pending`, `confirming`, `confirmed`, `reverted`, `failed`, and `timeout`.
- [ ] Never request, display, or handle the blockchain private key in frontend code.
- [ ] Verify `GET /health/ready` before beginning the demo.

## Demo-day startup instructions

1. Start the intended backend environment with the existing local database configuration.
2. Configure the single-admin `API_AUTH_KEY` through the process environment or deployment secret mechanism.
3. Confirm the frontend origin is configured in `CORS_ORIGINS`.
4. Start the FastAPI application.
5. Check:

   ```text
   GET /health
   GET /health/ready
   ```

6. Open `/docs` and confirm the API is reachable.
7. Use the frontend API key header for protected requests.
8. Use the existing registered report’s verification flow for the blockchain demonstration. Do not redeploy or submit an additional transaction.
9. Keep the existing `nexus.db` and Sepolia deployment metadata intact.

## Safe scope statement

This audit performed only tests, HTTP GET/OPTIONS checks, SQLite reads, OpenAPI inspection, and a read-only Sepolia contract verification call. It did not create reports, register threats, sign, broadcast, submit transactions, run migrations, modify `.env`, or alter blockchain state.

