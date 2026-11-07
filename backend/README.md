# Nexus Threat Intelligence API

FastAPI backend for evidence-backed URL, TLS, website, and scam-message analysis. User-controlled indicators are hashed before persistence where practical; raw threat-report indicators are never stored in the database or on-chain.

## Run locally

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

OpenAPI is available at `http://localhost:8000/docs`. Copy `.env.example` to `.env` for local Windows development; it uses the existing SQLite database at `./nexus.db` and does not require Docker or PostgreSQL. Unconfigured integrations return an explicit `not_configured` status. Install `requirements-blockchain.txt` in a Python 3.11 deployment when enabling the Web3 adapter.

Local development and Docker use separate database configurations:

- **Windows/Uvicorn:** keep `DATABASE_URL=sqlite:///./nexus.db` in `backend/.env`. This preserves and reuses the existing local SQLite database.
- **Docker Compose:** `docker-compose.yml` injects PostgreSQL's internal `db` hostname into the containerized API. The `db` hostname is only resolvable inside the Compose network and must not be used when running Uvicorn directly on Windows.

Do not run migrations as part of switching database URLs. If PostgreSQL is needed for local development outside Docker, use a host-resolvable PostgreSQL URL separately; otherwise leave the SQLite URL unchanged.

For reproducible Python 3.11 setup:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Set `API_AUTH_MODE=protected_demo` and a non-empty `API_AUTH_KEY` to require `X-API-Key` on all sensitive analysis, report, feed, dashboard, threat-report, and blockchain endpoints. `API_AUTH_MODE=demo` is local-development-only and permits an empty key. Configure the rate-limit values for the single-process MVP; use one worker for the hackathon demo.

AI is disabled unless `AI_ENABLED=true`, a supported `AI_PROVIDER` (`openai_compatible` or `gemini`), `AI_API_KEY`, and `AI_MODEL` are configured. Google Safe Browsing is enabled when `GOOGLE_SAFE_BROWSING_KEY` is set. Both integrations return explicit status values and never turn failures into positive matches.

Blockchain mode defaults to `mock`. Mock registration stores a local commitment and explicitly returns `on_chain: false`; it never signs, broadcasts, or contacts an RPC endpoint. Explicit Sepolia mode requires `BLOCKCHAIN_CHAIN_ID=11155111`, a Sepolia RPC URL, deployed contract address, private key, and matching account address. It validates the deployed bytecode and authorized operator, submits transactions through Web3.py, waits for receipts, and persists receipt metadata. It never falls back to mock mode.

Registration is idempotent by report. Transaction hashes are persisted immediately after broadcast; retries inspect the persisted hash and receipt rather than broadcasting a replacement. Transaction states are `pending`, `submitted`, `confirming`, `confirmed`, `failed`, `reverted`, and `timeout`. No uncontrolled polling loop or automatic replacement transaction is used.

Verification independently queries the configured Sepolia contract and recomputes the report commitment from the database. It never trusts a local blockchain row alone. A report is verified only when the on-chain commitment matches, the receipt succeeded, and the configured confirmation depth is reached; otherwise the API reports `not_registered`, `mismatch`, `pending`, `confirming`, `unavailable`, or `invalid_configuration`. Mock verification is explicitly local and never represents Ethereum state.

## Smart contract preparation

Phase 6.2 adds a local Hardhat project for the access-controlled `ThreatRegistry`; Phase 6.3 adds the optional Python Web3 adapter. The contract has not been deployed by this project and no live Sepolia transaction has been tested.

```powershell
npm install
npm run compile
npm run test:contracts
npm run export:abi
npm run validate:deployment
```

Deployment is manual only and requires a dedicated Sepolia test wallet, `BLOCKCHAIN_MODE=sepolia`, `BLOCKCHAIN_CHAIN_ID=11155111`, `BLOCKCHAIN_RPC_URL`, `BLOCKCHAIN_PRIVATE_KEY`, `BLOCKCHAIN_ACCOUNT_ADDRESS`, and `BLOCKCHAIN_CONTRACT_OWNER`. `npm run validate:deployment` validates configuration shape without contacting RPC. The deployment script refuses non-Sepolia networks and writes only public deployment metadata to `deployments/sepolia.json`.

```powershell
npm run deploy:sepolia
npm run verify:deployment
```

Do not use a mainnet key or RPC URL. Deployment and live transactions remain manual operations and are not performed during application startup or automated tests.

Schema management uses Alembic. New databases use `python -m alembic upgrade head`. The existing `nexus.db` was preserved; before adopting migrations against an existing database, back it up, verify its schema, and run `python -m alembic stamp 20261107_0001` rather than applying the initial create migration again.

## Database backup and restore

Stop the local API before copying the SQLite file to obtain a consistent backup:

```powershell
Copy-Item .\nexus.db .\backups\nexus.db.$(Get-Date -Format yyyyMMddHHmmss)
```

Restore only after stopping the API and confirming the backup path:

```powershell
Copy-Item .\backups\<backup-file> .\nexus.db
```

Verify the restored file without opening it for writes:

```powershell
.\.venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('file:nexus.db?mode=ro', uri=True); print(c.execute('PRAGMA integrity_check').fetchone()[0]); c.close()"
```

Do not overwrite the existing database during tests. PostgreSQL backups must use the environment's approved `pg_dump`/`pg_restore` process and credentials supplied outside source control; never put database passwords in this repository.

## Docker

```powershell
docker compose up --build
```

The URL analyzer blocks localhost, private, loopback, link-local, reserved, metadata, credential-bearing, and non-standard-port URLs. It does not execute page scripts or perform active exploitation.

See [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
