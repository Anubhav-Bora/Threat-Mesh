# ThreatMesh backend

ThreatMesh is an async FastAPI service for passive OSINT ingestion, approximate infrastructure
geolocation, confidence scoring, ATT&CK mapping, graph-based campaign leads, detection-content
generation, and retrieval-grounded CTI writing. It never scans indicators or automatically
resolves known-malicious hostnames.

## Run locally

Python 3.11+ and PostgreSQL 15+ with PostGIS are supported. Docker Compose normally supplies the
database URL shown below.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API is at `http://localhost:8000/api/v1`, interactive OpenAPI documentation is at
`http://localhost:8000/docs`, and liveness/readiness probes are `/health` and `/ready`.

For an isolated SQLite demo or test run, set:

```text
DATABASE_URL=sqlite+aiosqlite:///./threatmesh-demo.db
AUTO_CREATE_SCHEMA=true
SCHEDULER_ENABLED=false
```

Production should run `alembic upgrade head` during deployment and set
`AUTO_CREATE_SCHEMA=false`.

Load the pinned official Enterprise ATT&CK 19.2 STIX 2.1 release end to end with:

```powershell
python -m app.attack_mapping.sync
```

The loader has connect/read timeouts, a 70 MiB ceiling, and filters revoked and deprecated
techniques. For an offline-reviewed download use `python -m app.attack_mapping.sync --file PATH`.
ThreatMesh uses MITRE ATT&CK® data under MITRE's terms of use; ATT&CK® is a registered trademark
of The MITRE Corporation. Preserve this attribution when redistributing loaded data.

## Safe demo data

Loading data is always explicit. This idempotent command inserts synthetic documentation-range
IPs and clearly marks every raw record as demo data; it makes no network calls:

```powershell
python -m app.demo_seed
```

Running it again updates the same records instead of duplicating them. Live feed ingestion is
also explicit through `POST /api/v1/feeds/sync` or the scheduler.

Feed bodies are streamed and capped before parsing. The default
`FEED_MAX_RESPONSE_BYTES=8388608` limit (8 MiB) applies to both declared and chunked bodies.

Feed telemetry counts every raw attempted record and every normalization rejection. Mixed batches
are marked partial, while non-empty batches with no valid records fail. Timestamps more than ten
minutes ahead of the ingestion clock are rejected to prevent bad upstream clocks from inflating
recency and confidence. Summary feed health requires the latest successful completion to be within
twice the configured feed-sync interval; partial, failed, missing/skipped, and stale runs are not
counted as healthy.

## Credentials and privacy

- URLhaus and ThreatFox currently require a free abuse.ch Auth-Key. Register at
  `https://auth.abuse.ch/`, create an authentication key, and set `ABUSECH_AUTH_KEY`.
  When absent, those connectors return a clear skipped/configuration result without calling the
  services. Feodo ingestion remains independent.
- The default `LLM_PROVIDER=disabled` makes no AI request. For Gemini, create a free API key in
  Google AI Studio, then set `LLM_PROVIDER=gemini` and `GEMINI_API_KEY`. Only public OSINT facts
  and deterministic aggregates are sent. Free-tier content can be used by Google for product
  improvement or human review, so never add private incident data to this deployment.
- For local inference, install Ollama, pull `llama3.1:8b`, and set `LLM_PROVIDER=ollama` plus an
  appropriate `OLLAMA_BASE_URL`.
- The ip-api.com free endpoint is HTTP-only, rate limited, and licensed for non-commercial use.
  Lookups are limited to public literal IP addresses, paced below 45 requests/minute, and cached.
  Domains and URL hostnames are not resolved. Consider an approved commercial or offline provider
  for production use.
- Set a long random `ADMIN_API_KEY` in production. Mutation endpoints then require `X-API-Key`.

## Pipeline and endpoints

Scheduled jobs are independent and guarded against overlap: feed ingestion every three hours,
enrichment every 15 minutes, analysis every six hours, and an automatic report at 06:00 UTC.
For Vercel or other serverless hosting, set `SCHEDULER_ENABLED=false` and run this service
without built-in cron. In that mode, generate a report manually with `POST /api/v1/reports/generate`.
The persisted report cadence is still stored as weekly/monthly metadata, but the automatic trigger does
not run without a scheduler process.
Data retention is configured by `DATA_RETENTION_DAYS` (default: `30`) and is applied before each report
generation step.

## Deploy on Vercel

You can deploy this backend as a serverless function from `backend/` directly:

```powershell
cd backend
vercel
```

Keep these environment variables in the Vercel project (or commit-safe project env file):

```text
DATABASE_URL=postgresql+asyncpg://...
SCHEDULER_ENABLED=false
EXTERNAL_SCHEDULER_ENABLED=false
AUTO_CREATE_SCHEMA=false
CORS_ORIGINS=https://your-frontend.vercel.app
TRUSTED_HOSTS=.vercel.app
ADMIN_API_KEY=...
```

`AUTO_CREATE_SCHEMA` must be `false` once production schema already exists. You should run migrations
before first deploy (for example via CI or an admin run) and keep runtime to read-only schema management.
`TRUSTED_HOSTS` should include your custom domain if set, and `.vercel.app` is a broad fallback for the
default Vercel app hostname.

The persisted report cadence is selectable at runtime: weekly runs on the configured weekday
(Monday by default), while monthly runs on the first day of each month. Jobs do not run
immediately on startup unless `RUN_JOBS_ON_STARTUP=true`.

Key endpoints:

`GET /api/v1/iocs` accepts `provenance=all|live|demo` (default `all`) so operational
views can page live data without synthetic rows occupying the bounded result window.

- `GET /api/v1/iocs` — filtered/paginated GeoJSON FeatureCollection
- `GET /api/v1/stats/summary`, `/by-country`, `/by-malware-family`
- `GET /api/v1/stats/techniques/trending`
- `GET /api/v1/campaigns` and `/campaigns/{id}`
- `GET /api/v1/rules`, `POST /api/v1/rules/generate`, rule download
- `GET /api/v1/reports`, Markdown download
- `GET|PUT /api/v1/reports/schedule` — inspect or securely change weekly/monthly cadence
- `POST /api/v1/reports/generate` — manually generate a complete weekly report
- `POST /api/v1/assistant/ask` — constrained retrieval first, prose generation second
- `POST /api/v1/feeds/sync`, `/enrichment/run`, `/analysis/run`

IOC resources expose `is_demo`; the summary endpoint reports `demo_iocs`, `live_iocs`, and an
`empty|demo|live|mixed` `corpus_mode`, plus its live-first `analysis_scope`. Operational
aggregates, scoring, campaigns, rules, reports, and retrieval never combine synthetic and live
evidence. IOC source-row uniqueness is `(ioc_type, indicator_key, source_feed)`.

Campaigns are analytic leads, not attribution. Campaign graph edges require a shared canonical
indicator, malware family, or ASN; temporal proximity only bounds or weakly weights those semantic
links and never forms a campaign alone. IP geolocation is approximate observed-host context, not
attacker location. Generated Sigma and Suricata rules carry an explicit human-review notice and are
never deployed or committed automatically. Demo rule and report artifacts also retain an explicit
synthetic-data notice after download or export.

Campaign responses separate `relationship_evidence` (repeated canonical indicators, malware
families, and ASNs only) from `observed_context` (countries, sources, techniques, and descriptive
dimensions). They report distinct `unique_indicator_count` and source-row `observation_count`; a
single corroborated indicator never becomes a campaign by itself.

## Export detection-as-code artifacts

After review, operators can export stable filenames into repository-owned directories:

```powershell
python -m app.export_artifacts --rules-dir ..\rules --reports-dir ..\reports
```

Existing files are preserved. Pass `--overwrite` only when replacement is intentional. The default
export directories are ignored by Git; move a reviewed artifact into a deliberately versioned
location before normal change control. This preserves a meaningful human approval boundary.

## Verification

```powershell
ruff check app tests alembic
pytest --cov=app --cov-report=term-missing
alembic upgrade head
```

The test suite uses SQLite, injected feed/geolocation/LLM doubles, and no network access.

