# Nexus Backend Security Audit

**Audit date:** 2026-11-07  
**Scope:** FastAPI routes, request validation, outbound networking, secrets, persistence, provider integrations, and Sepolia transaction handling.

## Security posture summary

The backend has strong baseline protections for public URL fetching: scheme/port restrictions, credential-bearing URL rejection, DNS resolution, public-address checks, IP pinning, SNI/hostname validation, redirect revalidation, response-size limits, and bounded timeouts. Certificate verification is preserved through Python default SSL contexts.

The primary risks are exposure and operational hardening rather than an obvious unauthenticated code-execution path.

## Findings

| Severity | Finding | Evidence | Impact | Recommendation |
|---|---|---|---|---|
| HIGH | URL analysis can return and persist the normalized URL, including query values | `url_analysis.py`; `URLAnalysis.normalized_url`; report response | Tokens or tracking secrets in submitted query strings can be stored and exposed to public GET report clients | Redact query values before persistence/response, or store only scheme/host/path plus hashed query metadata |
| HIGH | Sensitive routes depend on the single demo `API_AUTH_KEY` being configured | `core/security.py`; sensitive routes now use `api_key_guard` | If the demo key is absent, sensitive routes remain intentionally open for local development | Configure a strong demo/admin `API_AUTH_KEY` before handover; fail closed at the deployment boundary if it is missing |
| MEDIUM | Rate limiting is in-memory and process-local | `core/security.py` | Bypass across workers/instances; restart resets limits | Use a shared limiter/gateway for production |
| MEDIUM | Readiness checks only the database | `main.py` | External providers and Sepolia may still be unavailable even when the API is ready to accept requests | Use `/health/ready` for database readiness and retain provider/blockchain checks as explicit demo smoke tests |
| MEDIUM | Blockchain lock and nonce coordination are process-local | `router.py`, `blockchain.py` | Multiple workers can race on the same account/nonce | Use a durable queue/nonce allocator or single transaction worker |
| MEDIUM | Error detail strings from blockchain verification/registration are returned to clients | `router.py` | Provider/internal topology or implementation details may leak | Return stable public error codes; log internal detail server-side |
| LOW | CORS defaults are development-oriented and configuration is permissive if misconfigured | `main.py`, `.env.example` | Incorrect origins could expose browser-accessible API responses | Use explicit production origins and integration tests |
| LOW | No request ID, audit log, metrics, or security event trail | Application-wide | Slower incident response and weak abuse visibility | Add structured telemetry with secret-safe fields |

## SSRF and DNS rebinding

### Verified protections

- Only `http` and `https` schemes are accepted.
- Credentials in URLs are rejected.
- Only ports 80 and 443 are accepted.
- Localhost, metadata, internal, private, loopback, link-local, and reserved destinations are rejected.
- DNS results are checked for public addresses.
- Passive HTTPS connects to the resolved IP while using the original hostname for SNI and certificate validation.
- Redirects are resolved and revalidated on every hop.
- Response size and redirect count are capped.

### Residual risk

DNS can change after initial resolution; the pinned connection reduces rebinding exposure for each request, but multi-hop redirects and future network changes should remain covered by integration tests.

## TLS

- TLS inspection and passive HTTPS use `ssl.create_default_context()`.
- Certificate verification and hostname validation remain enabled.
- No `verify=False` or `CERT_NONE` path was found.
- SSL verification diagnostics are sanitized and include only a hostname, verification code, and bounded reason.

## Authentication and authorization

- Optional `X-API-Key` authentication uses constant-time comparison.
- It protects URL analysis, message analysis, and threat-report creation only.
- GET report/feed/summary routes and blockchain registration/verification do not use the guard.
- There is no user identity, role, ownership, or per-report authorization model.

## Input and injection safety

- Pydantic validates URL, UUID, length, and enum inputs.
- SQLAlchemy expression APIs are used; no string-built SQL was found in application code.
- No file upload surface exists.
- AI prompts mark submitted content as untrusted and redact emails/phone numbers, but external provider data and submitted URLs should still be treated as sensitive.

## Secrets

- Settings use `SecretStr` for API keys and private keys.
- Provider keys are sent only to their configured providers.
- Current provider evidence sanitization does not include credentials or raw provider payloads.
- `.env` is Git-ignored.
- No secret values were printed during this audit.

## Blockchain signing and transaction reliability

- Mainnet chain ID and mainnet-looking RPC URLs are rejected.
- Sepolia chain ID, address formats, private-key format, derived signer address, deployed bytecode, ABI, and operator authorization are validated.
- Raw signing and broadcast happen only in the explicit Sepolia registration path.
- Transaction hashes are persisted after broadcast and receipts are rechecked.
- No replacement transaction or uncontrolled polling loop exists.
- Multi-process nonce coordination and durable recovery remain production gaps.

## Security test gaps

- Authenticated/unauthenticated behavior for every route.
- Cross-client and multi-worker rate-limit behavior.
- Query-string redaction in URL analysis responses and database rows.
- Production CORS configuration tests.
- Readiness failure tests.
- Concurrent blockchain registration with multiple workers.
- PostgreSQL security/integration tests.
