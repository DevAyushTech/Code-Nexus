# API contract

Base URL: `http://localhost:8000`.

Authentication uses one shared demo/admin API key. Set `API_AUTH_MODE=protected_demo` and a non-empty `API_AUTH_KEY` before exposing the backend to the frontend. In protected demo mode, send `X-API-Key` on every protected endpoint below. Missing or invalid keys return `401`; configured per-client limits return `429`. `API_AUTH_MODE=demo` is intended only for local development and permits an empty key.

- `GET /health` returns service status.
- `GET /health/ready` checks database readiness and returns `503` if the database is unavailable.
- `POST /api/v1/analyze/url` accepts `{"url":"https://example.com"}` and returns a report with `id`, `classification`, `risk_score`, `findings`, and integration statuses.
- `POST /api/v1/analyze/message` accepts `{"content":"..."}`. Message content is not returned.
- `GET /api/v1/reports/{id}` retrieves an analysis report.
- `GET /api/v1/dashboard/summary` returns counts by classification.
- `GET /api/v1/threats?skip=0&limit=50` lists threat reports.
- `POST /api/v1/threat-reports` accepts `indicator`, `report_type`, and `description`; the indicator is hashed and redacted in storage.
- `POST /api/v1/blockchain/register` accepts `{"report_id":"..."}` and creates a local cryptographic commitment in mock mode. In explicit Sepolia mode it submits the commitment to the configured deployed contract and returns receipt metadata only after a successful receipt.
- `GET /api/v1/blockchain/verify/{report_id}` returns local commitment status in mock mode, or queries `verifyThreat` on the configured Sepolia contract.

Protected endpoints:

- `POST /api/v1/analyze/url`
- `POST /api/v1/analyze/message`
- `GET /api/v1/reports/{id}`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/threats`
- `POST /api/v1/threat-reports`
- `GET /api/v1/threat-reports/{id}`
- `POST /api/v1/blockchain/register`
- `GET /api/v1/blockchain/verify/{id}`

Example:

```powershell
curl.exe -H "X-API-Key: <demo-key>" http://localhost:8000/api/v1/dashboard/summary
```

The generated OpenAPI document at `/docs` declares the `X-API-Key` API-key scheme for these operations.

Mock responses include `mode: "mock"` and `on_chain: false`; they never represent a blockchain transaction. Sepolia responses include `mode: "sepolia"` and explicit transaction states: `pending`, `submitted`, `confirming`, `confirmed`, `failed`, `reverted`, or `timeout`. A grounded Sepolia Etherscan `explorer_url` is included only when a transaction hash is persisted. There is no automatic fallback to mock mode.

When explicitly configured for Sepolia and a deployed contract, registration returns `mode: "sepolia"`, the actual `tx_hash`, `chain_id`, `contract_address`, receipt block, gas used, and confirmation count. It returns `status: "confirmed"` only after a successful receipt. RPC, configuration, authorization, gas, revert, and timeout failures are returned as explicit HTTP errors; no automatic mock fallback occurs.

Verification recomputes the canonical report commitment from the current database report and queries `verifyThreat(bytes32)`. Sepolia verification returns `verification_source: "sepolia"` and one of `verified`, `not_registered`, `mismatch`, `pending`, `confirming`, `unavailable`, or `invalid_configuration`. `verified: true` requires a matching on-chain record, a successful receipt when a transaction hash is available, and the configured confirmation depth. Mock verification returns `verification_source: "local_mock"`, `mode: "mock"`, `on_chain: false`, and never claims on-chain verification.

Example mock verification:

```json
{"verified": false, "status": "not_registered", "mode": "mock", "verification_source": "local_mock", "on_chain": false, "report_hash": "…", "tx_hash": null}
```

Example confirmed Sepolia verification:

```json
{"verified": true, "status": "verified", "mode": "sepolia", "verification_source": "sepolia", "on_chain": true, "chain_id": 11155111, "contract_address": "0x…", "reporter": "0x…", "on_chain_timestamp": 1730000000, "confirmations": 4, "receipt_status": 1}
```

Analysis responses include `evidence_quality`, `ai_analysis` (null when unavailable), and each finding includes `confidence`. A completed message AI object has `scam_indicators`, `extracted_urls`, `extracted_emails`, `extracted_phone_numbers`, `explanation`, `recommendations`, and `confidence` (0-1). Integration objects use `not_configured`, `unavailable`, `error`, `rate_limited`, `timeout`, or `completed` statuses.

Example completed message response:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "kind": "message",
  "target": "[message redacted]",
  "classification": "SUSPICIOUS",
  "risk_score": 43,
  "findings": [],
  "integrations": [
    {"source": "AI", "status": "completed", "analysis": {"scam_indicators": ["urgency manipulation"], "extracted_urls": [], "extracted_emails": [], "extracted_phone_numbers": [], "explanation": "Evidence-backed interpretation.", "recommendations": ["Verify independently."], "confidence": 0.91}}
  ],
  "evidence_quality": "mixed",
  "ai_analysis": {
    "scam_indicators": ["urgency manipulation"],
    "extracted_urls": [],
    "extracted_emails": [],
    "extracted_phone_numbers": [],
    "explanation": "Evidence-backed interpretation.",
    "recommendations": ["Verify independently."],
    "confidence": 0.91
  }
}
```

Errors use `{"detail":"..."}` for validation and resource errors, or `{"error":{"code":"internal_error","message":"..."}}` for unexpected failures.
