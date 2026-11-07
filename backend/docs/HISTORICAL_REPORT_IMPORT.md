# Historical report import

`scripts/import_historical_report.py` restores the preserved report
`14c7f538-f2d0-4320-865d-15b2d2631704` from `nexus.db` into the database named by
`DATABASE_URL` (which must be a PostgreSQL SQLAlchemy URL). It imports the parent report, blockchain record, and any URL,
TLS, threat-intelligence, security-finding, and scam-analysis rows for that
report. It does not import unrelated reports.

The source is opened with SQLite read-only mode. The script validates the
canonical report hash and original transaction hash before opening the target
transaction. It never imports private keys, calls the blockchain adapter, or
submits a transaction.

## Dry-run (default)

From `backend`, set `DATABASE_URL` through Render's environment or an approved
secret mechanism, then run:

```powershell
.\.venv\Scripts\python.exe scripts\import_historical_report.py
```

The command performs source validation, target conflict checks, and reports how
many rows would be inserted. It does not write.

## Apply once

1. Take a verified backup/snapshot of the Render PostgreSQL database.
2. Confirm migrations are at `20261107_0003`.
3. Run the dry-run and inspect its row count.
4. Confirm the target database is the intended staging database.
5. Run the same command with the explicit write flag:

```powershell
.\.venv\Scripts\python.exe scripts\import_historical_report.py --apply
```

The import uses one transaction. Existing identical rows are skipped. Any
different existing row or unique blockchain conflict aborts the transaction;
the script never overwrites or deletes records. If an apply run fails, verify
the database transaction was rolled back before retrying.

Afterward, call only:

```text
GET /api/v1/blockchain/verify/14c7f538-f2d0-4320-865d-15b2d2631704
```

Do not call `/api/v1/blockchain/register`. Verification may report
`confirming` until the configured confirmation depth is reached; do not
manually change the stored status or hash.

## Risks and rollback

- Never point `DATABASE_URL` at the source SQLite file or production before
  confirming the target.
- The source database is not modified, but it must be preserved unchanged.
- The script cannot recover data that is absent from the source.
- A conflict is a stop condition, not permission to overwrite the target.
- Rollback is database-level: restore the pre-import PostgreSQL backup if an
  operator determines a rollback is necessary. Do not delete rows manually.
