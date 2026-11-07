# Nexus Frontend Handover

## Architecture

The backend is a FastAPI application under `app/main.py`. API routes are in `app/api/v1/router.py`, Pydantic contracts are in `app/schemas/api.py`, and persistence uses SQLAlchemy with SQLite locally or PostgreSQL in Compose. URL analysis combines deterministic validation/scoring, SSRF-safe DNS/TLS/passive inspection, and isolated URLhaus/Safe Browsing providers. Message analysis is deterministic with optional advisory AI. Blockchain verification is read-only unless the explicit registration endpoint is intentionally used by an administrator.

## Integration map

| UI capability | Endpoint | Auth |
|---|---|---|
| Liveness | `GET /health` | Public |
| Database readiness | `GET /health/ready` | Public |
| URL scan | `POST /api/v1/analyze/url` | `X-API-Key` |
| Message scan | `POST /api/v1/analyze/message` | `X-API-Key` |
| Analysis detail | `GET /api/v1/reports/{report_id}` | `X-API-Key` |
| Dashboard | `GET /api/v1/dashboard/summary` | `X-API-Key` |
| Threat feed | `GET /api/v1/threats` | `X-API-Key` |
| Submit threat report | `POST /api/v1/threat-reports` | `X-API-Key` |
| Threat report detail | `GET /api/v1/threat-reports/{report_id}` | `X-API-Key` |
| Blockchain registration | `POST /api/v1/blockchain/register` | `X-API-Key` |
| Blockchain verification | `GET /api/v1/blockchain/verify/{report_id}` | `X-API-Key` |

## TypeScript contracts

```ts
type Classification = "LOW" | "SUSPICIOUS" | "HIGH" | "CONFIRMED_MALICIOUS" | "INCONCLUSIVE";
type ProviderStatus = "completed" | "not_configured" | "unavailable" | "rate_limited" | "error" | "inconclusive";
type RegistrationStatus = "mock" | "pending" | "submitted" | "confirming" | "confirmed" | "failed" | "reverted" | "timeout";
type VerificationStatus = "verified" | "not_registered" | "pending" | "confirming" | "mismatch" | "rpc_unavailable" | "invalid_configuration";

interface Finding {
  name: string; severity: string; evidence: string; source: string;
  explanation: string; recommendation: string; confidence: number;
}
interface Integration {
  source?: string; status: string; match?: boolean; evidence?: unknown;
  error?: string; confidence: number; checked_at?: string;
  [key: string]: unknown;
}
interface EvidenceSummary {
  confirmed_matches: Integration[];
  technical_indicators: Integration[];
  heuristic_findings: Finding[];
  inconclusive_or_unavailable: Integration[];
}
interface AnalysisResponse {
  id: string; kind: string; target: string; classification: Classification;
  risk_score: number; findings: Finding[]; integrations: Integration[];
  evidence_quality: string; evidence_summary: EvidenceSummary;
  ai_analysis: Record<string, unknown> | null;
}
interface ThreatReportResponse {
  id: string; report_type: "url" | "domain" | "message" | "other";
  description: string; created_at: string;
}
interface ThreatFeedResponse {
  items: ThreatReportResponse[]; skip: number; limit: number;
}
interface BlockchainRegistrationResponse {
  status: string; mode: string; on_chain: boolean; report_id: string;
  report_hash: string; tx_hash?: string | null; chain_id?: number | null;
  contract_address?: string | null; block_number?: number | null;
  gas_used?: number | null; confirmations?: number | null;
  explorer_url?: string | null;
}
interface BlockchainVerificationResponse {
  verified: boolean; status: string; mode: string;
  verification_source: string; on_chain: boolean; report_hash: string;
  tx_hash?: string | null; chain_id?: number | null;
  contract_address?: string | null; reporter?: string | null;
  on_chain_timestamp?: number | null; confirmations?: number | null;
  receipt_status?: number | null; block_number?: number | null;
  error_code?: string | null;
}
```

## API service shape

Keep the API base URL and key outside browser source. In the demo architecture, a trusted server-side proxy should add `X-API-Key`; never expose the shared key in a public bundle.

```ts
async function request<T>(baseUrl: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) throw new Error(`API request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

const analyzeUrl = (base: string, url: string) =>
  request<AnalysisResponse>(base, "/api/v1/analyze/url", {
    method: "POST", body: JSON.stringify({ url }),
  });

const getVerification = (base: string, reportId: string) =>
  request<BlockchainVerificationResponse>(base, `/api/v1/blockchain/verify/${reportId}`);
```

## UI states

- Scan: `loading` → report result, validation error, rate-limited, or unavailable.
- Classification: `CONFIRMED_MALICIOUS` is provider-backed; `HIGH`, `SUSPICIOUS`, and `LOW` are deterministic findings; `INCONCLUSIVE` means insufficient evidence, not safe.
- Providers: `completed`/`match:false` is a successful no-match. `not_configured`, `unavailable`, `rate_limited`, `error`, and `inconclusive` must be shown as unavailable/inconclusive, never clean.
- Blockchain: display `pending`, `confirming`, `verified`, `not_registered`, `mismatch`, `rpc_unavailable`, and `invalid_configuration` distinctly. `on_chain` is authoritative only when true with `status:"verified"` for verification.

## Integration sequence

1. Configure the backend base URL and approved CORS origin.
2. Verify `/health`, then `/health/ready`.
3. Implement URL/message submission and preserve returned UUIDs.
4. Implement report retrieval and evidence grouping.
5. Add dashboard and threat feed pagination/filtering.
6. Add read-only blockchain verification display.
7. Add threat-report submission only where the operator workflow requires it.
8. Do not invoke blockchain registration automatically.

## Manual handover checklist

- Confirm backend is running and `/docs` loads.
- Confirm protected demo mode is configured by the operator without exposing the key to browser code.
- Confirm frontend origin is in `CORS_ORIGINS`.
- Submit one benign URL and one controlled message.
- Verify the returned report can be retrieved by UUID.
- Verify `INCONCLUSIVE` is not rendered as clean.
- Verify threat feed `skip`, `limit`, and `report_type`.
- Verify `/health/ready` failure is shown as backend unavailable.
- Verify read-only blockchain verification does not submit a transaction.
- Verify API errors do not display raw exception text or secrets.
