# Operations guide

This guide covers a single-instance Docker Compose deployment. It is suitable
for local analysis and portfolio demonstrations, not an internet-exposed
multi-tenant service.

## First start

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
```

The Compose database image initializes PostGIS. The backend container runs the
versioned Alembic migration before starting the API. To run it explicitly:

```powershell
docker compose exec backend alembic upgrade head
```

`AUTO_CREATE_SCHEMA=false` is the Compose default. Treat migrations as a
release step and back up the database before upgrading an existing
installation. The opt-in auto-create setting exists only for lightweight local
development and tests.

## Health and logs

```powershell
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/ready
docker compose logs --tail=200 backend
docker compose logs --tail=200 db
```

`/health` reports process liveness. `/ready` checks whether the configured
database can answer a query. Each API response includes an `X-Request-ID`; use
that value to correlate a client error with structured application logs.

## Deterministic demo data

```powershell
docker compose exec backend python -m app.demo_seed
```

The seeder uses documentation-only address ranges and fictional ASN names. It
is idempotent, performs no network calls, and never runs automatically. Use a
separate database or remove the demo data before assessing live-feed results.

On Linux, set `HOST_UID` and `HOST_GID` in `.env` to the output of `id -u` and
`id -g`. Compose runs the backend as that non-root identity so exported files
in the bind-mounted `rules/` and `reports/` directories remain writable and
owned by the operator. The example values match the common first-user UID/GID
of 1000.

## Live pipeline operations

Scheduled collection, enrichment, analysis, and report generation are enabled
or disabled through `.env`. Report cadence is persisted in the database and can
be changed between **Weekly** and **Monthly** from the Reports workspace. Weekly
runs occur on Monday at 06:00 UTC and cover the previous complete calendar week;
monthly runs occur on day one at 06:00 UTC and cover the previous complete
calendar month. Changing cadence schedules the next run and never generates a
report immediately.

The embedded scheduler must remain running for a report to be created. It does
not backfill a run missed while the backend was stopped. Only one scheduler
process should run for a database. If the API is scaled horizontally, disable
its embedded schedulers and move jobs to one dedicated worker or an external
scheduler.

Administrative mutation routes require `X-API-Key` whenever `ADMIN_API_KEY` is
configured. They are disabled in production if no key is configured. Generate
a local value, place it in `.env`, and restart the backend:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
docker compose up -d backend
```

Then invoke an operation with that value in the header, for example:

```powershell
$env:ADMIN_API_KEY = Read-Host 'Enter the same ADMIN_API_KEY value from .env'
$headers = @{ 'X-API-Key' = $env:ADMIN_API_KEY }
Invoke-RestMethod -Method Post -Headers $headers http://localhost:8000/api/v1/feeds/sync
Invoke-RestMethod -Method Post -Headers $headers http://localhost:8000/api/v1/enrichment/run
Invoke-RestMethod -Method Post -Headers $headers http://localhost:8000/api/v1/analysis/run
```

Compose reads `.env` when it creates a container, but PowerShell does not load
that file into the current shell. The `Read-Host` step deliberately avoids
placing the key in shell history.

The Reports workspace follows the same boundary when a cadence is changed: it
asks for the administrator key only when **Save schedule** is selected, sends it
once in the `X-API-Key` header, and immediately clears it from component memory.
The key is never stored in browser storage or compiled into the frontend.

Inspect recent connector outcomes without an admin credential:

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/feeds/status
```

A missing abuse.ch key produces an explicit skipped result for URLhaus and
ThreatFox while Feodo can still run. Connector failures are isolated so one
unavailable source does not discard another source's successful records.
Feed bodies are streamed and rejected above `FEED_MAX_RESPONSE_BYTES` (8 MiB
by default), including when an upstream omits or understates `Content-Length`.

## ATT&CK catalog

Load the pinned official Enterprise ATT&CK 19.2 STIX 2.1 bundle:

```powershell
docker compose exec backend python -m app.attack_mapping.sync
```

For an offline or independently verified bundle:

```powershell
docker compose cp .\enterprise-attack.json backend:/tmp/enterprise-attack.json
docker compose exec backend python -m app.attack_mapping.sync --file /tmp/enterprise-attack.json
```

The loader rejects an oversized download and filters revoked or deprecated
attack-pattern objects. Pinning the release makes a rebuild reproducible;
updating it should be a reviewed dependency change.

## Exporting analyst artifacts

Rules and reports remain in the database until an operator explicitly exports
them. This avoids an application process mutating Git history or overwriting
analyst edits.

```powershell
docker compose exec backend python -m app.export_artifacts `
  --rules-dir /app/rules `
  --reports-dir /app/reports
```

Existing files are preserved by default. Review, test, and tune the outputs,
then commit approved artifacts with normal change control. `--overwrite` is an
explicit opt-in for replacing files with the same stable names.

## Deployment checklist

- Change the default PostgreSQL password in both `POSTGRES_PASSWORD` and the
  URL-encoded credential inside `DATABASE_URL`; keep `.env` outside deployment
  artifacts.
- Set `ENVIRONMENT=production`, `AUTO_CREATE_SCHEMA=false`, and a long random
  `ADMIN_API_KEY`.
- Restrict `TRUSTED_HOSTS` and `CORS_ORIGINS` to exact deployed origins.
- Terminate TLS at a trusted reverse proxy and do not expose PostgreSQL.
- Replace the HTTP-only, non-commercial ip-api adapter for commercial or
  higher-assurance use.
- Restrict the ArcGIS browser key by origin, privilege, and expiry.
- Keep Gemini and abuse.ch keys server-side and rotate them after suspected
  disclosure.
- Back up PostgreSQL and test restoration on a separate instance.
- Run only one embedded scheduler per database.
- Monitor connector freshness and error state; a healthy web process does not
  guarantee that every upstream source is current.
- Never expose an unauthenticated Ollama listener outside a trusted host.
