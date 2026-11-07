# Nexus Frontend Integration Guide

## Base URL and documentation

Configure the API base URL per environment, for example:

```text
http://localhost:8000
```

Interactive OpenAPI documentation is available at `/docs`; the OpenAPI schema is available at `/openapi.json`.

## Authentication

When `API_AUTH_KEY` is configured, send:

```http
X-API-Key: <configured key>
```

It is required on:

- `POST /api/v1/analyze/url`
- `POST /api/v1/analyze/message`
- `POST /api/v1/threat-reports`

The current backend does not require authentication on GET routes or blockchain routes. Treat that as a deployment security gap, not as a frontend authorization guarantee.

## Endpoint contract

### `GET /health`

```json
{"status":"ok","service":"nexus-threat-intelligence"}
```

### `POST /api/v1/analyze/url`

Request:

```json
{"url":"https://example.com"}
```

Validation: absolute HTTP(S) URL; backend additionally rejects credentials, unsafe destinations, unsupported ports, private/reserved addresses, and unsafe redirects.

Response shape:

```json
{
  "id":"00000000-0000-0000-0000-000000000000",
  "kind":"url",
  "target":"https://example.com",
  "classification":"INCONCLUSIVE",
  "risk_score":0,
  "findings":[],
  "integrations":[
    {"source":"URLhaus","status":"not_configured","match":false},
    {"source":"Google Safe Browsing","status":"not_configured","match":false},
    {"source":"TLS","status":"valid","expires_at":"2099-01-01T00:00:00+00:00"},
    {"source":"passive_website_inspection","status":"completed","status_code":200}
  ],
  "evidence_quality":"mixed",
  "ai_analysis":null
}
```

Provider statuses include `not_configured`, `completed`, `unavailable`, `error`, `rate_limited`, and `timeout`. A provider failure does not prevent deterministic analysis or the other provider from completing.

### `POST /api/v1/analyze/message`

Request:

```json
{"content":"Urgent payment request: send your OTP."}
```

Content length: 1–50,000 characters.

Response uses `AnalysisResponse`; `target` is `[message redacted]`. `ai_analysis` is either `null` or a validated object with scam indicators, extracted IOCs, explanation, recommendations, and confidence.

### `GET /api/v1/reports/{report_id}`

Returns an `AnalysisResponse`. Message targets remain redacted. Missing UUIDs return 404.

### `GET /api/v1/dashboard/summary`

```json
{"total":2,"classifications":{"SUSPICIOUS":1,"INCONCLUSIVE":1}}
```

### `GET /api/v1/threats?skip=0&limit=50`

```json
{"items":[],"skip":0,"limit":50}
```

`skip` must be non-negative; `limit` is 1–100. There are no filtering or cursor parameters.

### `POST /api/v1/threat-reports`

Request:

```json
{"indicator":"https://example.com","report_type":"url","description":"Suspicious destination"}
```

`report_type` is one of `url`, `domain`, `message`, `other`. The stored indicator is redacted and hashed.

### `GET /api/v1/threat-reports/{report_id}`

Returns:

```json
{
  "id":"00000000-0000-0000-0000-000000000000",
  "report_type":"url",
  "description":"Suspicious destination",
  "created_at":"2026-11-07T00:00:00"
}
```

### `POST /api/v1/blockchain/register`

Request:

```json
{"report_id":"00000000-0000-0000-0000-000000000000"}
```

Mock response:

```json
{"status":"mock","mode":"mock","on_chain":false,"report_id":"...","report_hash":"...","tx_hash":null}
```

Sepolia response fields include `status`, `mode`, `on_chain`, `report_id`, `report_hash`, `tx_hash`, `chain_id`, `contract_address`, `block_number`, `gas_used`, `confirmations`, and `explorer_url`.

Possible transaction states: `pending`, `submitted`, `confirming`, `confirmed`, `failed`, `reverted`, `timeout`.

### `GET /api/v1/blockchain/verify/{report_id}`

Mock:

```json
{
  "verified":false,
  "status":"not_registered",
  "mode":"mock",
  "verification_source":"local_mock",
  "on_chain":false,
  "report_hash":"...",
  "tx_hash":null
}
```

Sepolia verification includes `verified`, `status`, `mode`, `verification_source`, `on_chain`, `report_hash`, `tx_hash`, `chain_id`, `contract_address`, `reporter`, `on_chain_timestamp`, `confirmations`, `receipt_status`, `block_number`, and optional `error_code`.

Verification statuses include `verified`, `not_registered`, `mismatch`, `pending`, `confirming`, `unavailable`, and `invalid_configuration`.

## Error contract

Generic server errors:

```json
{"error":{"code":"internal_error","message":"An internal error occurred."}}
```

Expected HTTP errors:

- `401`: missing/invalid API key.
- `400`: unsafe or invalid URL.
- `404`: report not found.
- `422`: request validation failure.
- `429`: application rate limit or provider rate-limited integration status.
- `502`: blockchain RPC/transaction failure during registration.
- `503`: blockchain configuration/dependency failure.

Frontend states should distinguish loading, completed, not configured, unavailable, error, rate limited, pending, confirming, confirmed, reverted, timeout, and invalid configuration.

## Classification and status enums

Deterministic classifications: `INCONCLUSIVE`, `LOW`, `SUSPICIOUS`, `HIGH`, `CONFIRMED_MALICIOUS`.

Finding severities currently include `low` and `medium`; frontend should not assume the set is closed.

## CORS

The backend allows configured `CORS_ORIGINS`, `GET`/`POST`, and `Content-Type`/`Authorization` headers. Credentials are disabled. Configure the frontend origin explicitly in the backend environment.

## Frontend integration cautions

- Do not treat `not_configured` or `unavailable` as a clean result.
- Do not treat `INCONCLUSIVE` as safe.
- Do not expose transaction signing controls in the frontend; signing is backend-controlled.
- Avoid rendering provider evidence as trusted HTML.
- The backend currently may return URL targets containing query strings; treat them as sensitive and avoid displaying them without redaction.

