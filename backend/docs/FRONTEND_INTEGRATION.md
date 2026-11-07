# Frontend integration

Use the REST base URL from the deployment environment and send JSON with `Content-Type: application/json`.

The hackathon deployment uses one shared demo/admin API key. In protected demo mode, send it as `X-API-Key` on URL analysis, message analysis, report retrieval, dashboard, threat feed, threat-report creation/retrieval, and blockchain registration/verification. Missing or invalid keys return HTTP 401. The local-only `API_AUTH_MODE=demo` mode may be used without a key; do not expose that mode to judges.

Public health endpoints are `GET /health` and `GET /health/ready`. The latter checks database readiness. Treat `classification` as an evidence summary, not proof of safety. Display `integrations[].status` because external sources may be unavailable.

Analysis responses include `id`, `kind`, `target`, `classification`, `risk_score`, `findings`, `integrations`, `evidence_quality`, and optional `ai_analysis`. New URL reports redact query values from `target` and persistence. Dashboard responses include `total`, `total_reports`, and `classifications`; threat feeds include `items`, `skip`, and `limit`.

Blockchain registration and verification responses are typed in OpenAPI. Registration states include `pending`, `submitted`, `confirming`, `confirmed`, `failed`, `reverted`, and `timeout`. Verification never submits a transaction.

Authentication example:

```http
X-API-Key: <demo-key>
```

Never place the API key, blockchain private key, provider credentials, or RPC credentials in frontend source code.

For message analysis, render `ai_analysis` only when it is non-null and its corresponding integration has `status: "completed"`. AI interpretation is advisory; `classification`, `risk_score`, and deterministic findings remain authoritative.
