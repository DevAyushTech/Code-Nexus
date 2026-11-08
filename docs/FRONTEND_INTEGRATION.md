# Frontend integration

Use the REST base URL from the deployment environment and send JSON with `Content-Type: application/json`. When `API_AUTH_KEY` is configured, send it as `X-API-Key` on URL analysis, message analysis, and threat-report submission. Failed authentication returns HTTP 401 and rate limits return HTTP 429. Treat `classification` as an evidence summary, not proof of safety. Display `integrations[].status` because external sources may be unavailable.

For message analysis, render `ai_analysis` only when it is non-null and its corresponding integration has `status: "completed"`. AI interpretation is advisory; `classification`, `risk_score`, and deterministic findings remain authoritative.
