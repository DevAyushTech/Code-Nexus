# Nexus Frontend Integration Guide

## Runtime

Local API base URL: `http://localhost:8000`. Interactive OpenAPI/Swagger UI is at `/docs`; the JSON contract is at `/openapi.json`.

Run the backend from `backend`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Local development normally uses the existing SQLite URL. A protected deployment must use `API_AUTH_MODE=protected_demo`. Supabase Auth handles email sign-up/login and supplies the access token; the backend verifies it locally using the project's public JWKS. The legacy API key remains available for compatibility.

The configured frontend origin must be present in `CORS_ORIGINS`. The backend allows `GET`, `POST`, and the `Content-Type`, `Authorization`, and `X-API-Key` request headers. CORS credentials are disabled.

## Authentication

After signing up or logging in with Supabase Auth, send the returned access token to protected routes:

```http
Authorization: Bearer <supabase-access-token>
Content-Type: application/json
```

Supabase access tokens must be valid, unexpired ES256 JWTs issued for this project with audience `authenticated`. Missing or invalid credentials return `401`; an invalid bearer token never falls back to `X-API-Key`. Health routes are public. The existing API-key alternative is:

```http
X-API-Key: <demo-key>
```

Never expose the API key, Supabase secret key, or service-role key in browser code or a public bundle.

## Endpoint contract

### `GET /health` — public liveness

Response `200`:

```json
{"status":"ok","service":"nexus-threat-intelligence"}
```

### `GET /health/ready` — public database readiness

Executes `SELECT 1` on the configured database. Response `200`:

```json
{"status":"ready","database":"ok"}
```

Database failure returns `503`:

```json
{"detail":"Database is unavailable."}
```

### `POST /api/v1/analyze/url` — URL analysis

Request body:

```json
{"url":"https://example.com/login"}
```

`url` must be a valid HTTP(S) URL accepted by `HttpUrl`, and the backend additionally rejects credentials, private destinations, disallowed ports, unsafe DNS results, and unsafe redirects. Success is `201` with `AnalysisResponse`:

```json
{
  "id":"00000000-0000-0000-0000-000000000000",
  "kind":"url",
  "target":"https://example.com/login",
  "classification":"INCONCLUSIVE",
  "risk_score":0,
  "findings":[],
  "integrations":[
    {"source":"URLhaus","status":"not_configured","match":false,"confidence":0.0,"checked_at":"2026-11-08T00:00:00+00:00"},
    {"source":"Google Safe Browsing","status":"completed","match":false,"confidence":0.9,"evidence":[],"checked_at":"2026-11-08T00:00:00+00:00"},
    {"source":"TLS","status":"valid"},
    {"source":"passive_website_inspection","status":"completed"}
  ],
  "evidence_quality":"mixed",
  "evidence_summary":{
    "confirmed_matches":[],
    "technical_indicators":[
      {"source":"TLS","status":"valid"},
      {"source":"passive_website_inspection","status":"completed"}
    ],
    "heuristic_findings":[],
    "inconclusive_or_unavailable":[
      {"source":"URLhaus","status":"not_configured","match":false,"confidence":0.0,"checked_at":"2026-11-08T00:00:00+00:00"}
    ]
  },
  "ai_analysis":null
}
```

New URL targets and integration URLs omit query values. Provider `completed` with `match:false` means that provider successfully returned no match. `not_configured`, `unavailable`, `rate_limited`, `error`, and `inconclusive` do **not** mean clean or safe. A provider match produces `classification:"CONFIRMED_MALICIOUS"`.

Errors: `401` auth, `400` URL safety/validation rejection, `429` rate limit, `422` request-schema validation, and sanitized `500` unexpected failure.

### `POST /api/v1/analyze/message` — message analysis

Request body:

```json
{"content":"Urgent: verify your account and send the code."}
```

`content` is required and limited to 50,000 characters. Success is `201` with the same `AnalysisResponse` shape and `kind:"message"`. The response target is always `"[message redacted]"`. Deterministic findings cover urgency, payment, credential language, suspicious links, and possible impersonation. `ai_analysis` is nullable and advisory only.

Errors: `401`, `400` for empty content after service validation, `422` for malformed/oversized JSON, `429`, and sanitized `500`.

### `GET /api/v1/reports/{report_id}` — analysis report retrieval

Requires a UUID path value and the API key. Success is `200` with the stored `AnalysisResponse`; missing UUID records return `404`:

```json
{"detail":"Report not found."}
```

Message targets remain redacted. URL query values remain redacted. This route reconstructs stored findings, provider integrations, TLS data, evidence grouping, and optional AI output.

### `GET /api/v1/dashboard/summary` — dashboard counts

No query parameters. Success `200`:

```json
{"total":12,"total_reports":12,"classifications":{"LOW":5,"SUSPICIOUS":4,"CONFIRMED_MALICIOUS":2,"INCONCLUSIVE":1}}
```

### `GET /api/v1/threats` — threat feed

Query parameters:

- `skip`: integer, minimum `0`, default `0`.
- `limit`: integer `1..100`, default `50`.
- `report_type`: optional `url`, `domain`, `message`, or `other`.

Success `200`:

```json
{"items":[{"id":"00000000-0000-0000-0000-000000000000","report_type":"url","description":"Suspicious link","created_at":"2026-11-08T00:00:00"}],"skip":0,"limit":50}
```

Invalid query values return `422`; authentication returns `401`.

### `POST /api/v1/threat-reports` — submit threat report

Request:

```json
{"indicator":"https://example.com","report_type":"url","description":"Suspicious destination"}
```

`indicator` is 1–2048 characters; `description` is 1–10,000 characters; `report_type` is `url`, `domain`, `message`, or `other`. Success `201` returns:

```json
{"id":"00000000-0000-0000-0000-000000000000","report_type":"url","description":"Suspicious destination","created_at":"2026-11-08T00:00:00"}
```

The indicator is redacted from storage and hashed for lookup. Errors: `401`, `422`, `503` persistence failure, or sanitized `500`.

### `GET /api/v1/threat-reports/{report_id}` — threat report retrieval

Requires a UUID and API key. Success is the same `ThreatReportResponse`; missing records return `404` with `{"detail":"Threat report not found."}`.

### `POST /api/v1/blockchain/register` — blockchain registration

Request:

```json
{"report_id":"00000000-0000-0000-0000-000000000000"}
```

Requires an existing analysis report. In mock mode it creates a local commitment and returns `mode:"mock", on_chain:false`. In explicit Sepolia mode it may return `pending`, `submitted`, `confirming`, `confirmed`, `failed`, `reverted`, or `timeout`, with optional transaction/receipt metadata. `on_chain` is true only for confirmed, confirmation-sufficient evidence. It never falls back from Sepolia to mock. Verification status is separate from registration status.

Errors include `401`, `404`, `502` RPC/transaction failures, `503` configuration/service failures, `422` invalid UUID, or sanitized `500`. Do not call this endpoint automatically during page load.

### `GET /api/v1/blockchain/verify/{report_id}` — read-only verification

Requires an existing analysis report and API key. It never submits a transaction. Response fields include `verified`, `status`, `mode`, `verification_source`, `on_chain`, `report_hash`, optional transaction/chain/contract/reporter/timestamp/receipt/confirmation fields, and `error_code`.

Sepolia statuses:

- `verified`: hash matches, receipt succeeded, and confirmation depth is sufficient; `verified:true`, `on_chain:true`.
- `not_registered`: contract has no matching commitment.
- `pending`: transaction/receipt is not yet available.
- `confirming`: commitment or receipt exists but confirmation depth is insufficient.
- `mismatch`: local commitment or receipt evidence does not match.
- `rpc_unavailable`: read-only provider unavailable.
- `invalid_configuration`: Sepolia configuration is invalid.

`reverted` is a registration/receipt state; verification of a reverted receipt is represented as a non-verified mismatch/error result. Mock verification uses `verification_source:"local_mock"` and never claims Ethereum state.

## Client behavior

Show loading while requests are in flight. Treat `401` as an authentication/configuration problem, `422` as a request-form problem, `429` as retryable after the configured window, `503` as unavailable/readiness failure, and `502` as an upstream blockchain failure. Do not retry POST blockchain registration automatically. Report retrieval and read-only verification may be retried conservatively after network timeouts.

Store returned report IDs as opaque UUID strings. Do not calculate blockchain hashes in the frontend. Poll or refresh read-only verification only when the user requests it and display `pending`/`confirming` separately from `verified`.
