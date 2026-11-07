# Nexus Backend Completion Roadmap

## P0 — Before production frontend exposure

1. **Protect read and blockchain routes**
   - Require authentication for report retrieval, threat feed, dashboard, and blockchain operations.
   - Add authorization/ownership semantics if multiple users will share the deployment.
2. **Redact URL secrets**
   - Stop persisting and returning raw query values from URL analysis.
   - Preserve only safe host/path metadata and query-key/hash metadata.
3. **Add readiness checks**
   - Keep `/health` as liveness.
   - Add bounded database/provider readiness checks with safe status output.
4. **Harden blockchain submission**
   - Move signing/broadcast to a single durable worker or implement durable nonce/idempotency coordination.
   - Define operator-facing recovery for pending/timeout/failed records.
5. **Lock production CORS and environment policy**
   - Require explicit production origins and mandatory API authentication.

## P1 — Reliability and observability

1. Add structured request IDs and secret-safe logs.
2. Add metrics for latency, timeout, retry, provider status, database errors, and blockchain states.
3. Add circuit breakers or provider backoff after repeated failures.
4. Move URL provider/TLS/passive inspection work to background jobs if request latency is unacceptable.
5. Add cursor pagination and filtering to the threat feed.
6. Add retention and deletion policies for reports, provider evidence, and operational metadata.

## P2 — Contract and platform quality

1. Replace untyped integration dictionaries with versioned response models.
2. Add explicit public error schemas and stable error-code enums.
3. Add PostgreSQL CI/integration coverage in addition to SQLite.
4. Add API compatibility tests generated from OpenAPI.
5. Add dependency vulnerability scanning and lockfile update policy.
6. Add deployment smoke tests that validate the configured Sepolia contract without sending transactions.

## Test expansion

- Auth matrix for every route.
- Query-redaction tests across API response and database persistence.
- Multi-worker rate-limit tests.
- PostgreSQL migration and transaction tests.
- Concurrent blockchain registration/nonce tests.
- Readiness and dependency outage tests.
- End-to-end provider fixtures for URLhaus and Safe Browsing.
- Browser-facing CORS/OpenAPI contract tests.

## Definition of done

The backend is frontend-ready for a controlled MVP when:

- All public data and mutation routes have explicit authentication/authorization decisions.
- URL query secrets are never persisted or returned.
- Readiness is distinct from liveness.
- Provider failure states are observable and do not alter deterministic safety semantics.
- Blockchain submission is idempotent and safe across multiple workers.
- SQLite and PostgreSQL migration paths are tested.
- OpenAPI response models and stable error codes are versioned.
- CI covers unit, integration, security, and API contract tests.

