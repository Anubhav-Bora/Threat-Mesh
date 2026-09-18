# ThreatMesh

**Passive OSINT in. Analyst-ready context out.**

[![CI](https://github.com/Anubhav-Bora/Threat-Mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/Anubhav-Bora/Threat-Mesh/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](backend/pyproject.toml)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=07111f)](frontend/package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](LICENSE)

ThreatMesh is a self-hosted cyber-threat intelligence workspace. It collects
public indicators from community feeds, preserves provenance, enriches literal
IP addresses, maps known malware behavior to MITRE ATT&CK, groups related
infrastructure into campaign candidates, and turns high-confidence observations
into reviewable detection content. A geospatial analyst console makes the
result explorable without presenting estimated location or generated prose as
ground truth.

The useful security work is deterministic. Gemini or a local Ollama model can
write a report and phrase retrieval-backed answers, but neither provider can
change confidence, technique mapping, clustering, or response decisions.

## What is included

| Capability | Implementation |
|---|---|
| Passive collection | Bounded async connectors for URLhaus, ThreatFox, and Feodo Tracker with normalized, idempotent upserts and feed-run history |
| Geospatial context | Cached backend-only IP/ASN enrichment, PostGIS geography points, clustering, heatmap, and illustrative geodesic uncertainty views |
| Intelligence analysis | Versioned confidence snapshots with per-signal evidence, ATT&CK STIX catalog/mapping, and graph-based Louvain campaign candidates |
| Detection engineering | Stable Sigma and Suricata templates with provenance and mandatory human-review labeling |
| Analyst reporting | On-demand, evidence-bounded weekly CTI snapshots that persist every requested version and open immediately after generation |
| Natural-language access | Hybrid assistant with Auto, Threat data, and General modes; bounded conversation context; server-validated evidence IDs for live-data claims; and exact record pivots instead of unrestricted text-to-SQL |
| Operations | Embedded or external scheduled jobs, health/readiness probes, audit-friendly feed runs, rate limits, admin-key protection, Alembic migrations, and deterministic demo seeding |
| Portfolio UX | Responsive React/TypeScript console with overview, bulk investigation, indicators, campaigns, ATT&CK, rules, reports, assistant, and settings workspaces |

## Architecture

```mermaid
flowchart LR
    Feeds[URLhaus · ThreatFox · Feodo] --> Ingest[Validate · normalize · upsert]
    Ingest --> DB[(PostgreSQL + PostGIS)]
    DB --> Enrich[Cached IP/ASN enrichment]
    Enrich --> DB
    DB --> Analyze[Score · ATT&CK · cluster · rules]
    Analyze --> DB
    DB --> API[FastAPI / GeoJSON]
    API --> UI[React + ArcGIS analyst console]
    DB --> Retrieve[Constrained retrieval]
    Retrieve --> LLM{Gemini · Ollama · disabled}
    LLM --> API
```

Local learning and interview notes are kept under `docs/` and intentionally
ignored by Git. The public README contains the supported setup, architecture,
safety, and deployment contract.

The included deployment templates support a full stack Vercel layout:
Vercel-hosted frontend (`frontend/`) and Vercel-hosted FastAPI backend (`backend/`)
connected to an external PostgreSQL/PostGIS database.

For Vercel, deploy both layers separately:

- `frontend/` as a Vite static project.
- `backend/` as a Python serverless function project using `backend/vercel.json`.

Set `SCHEDULER_ENABLED=false` in backend deployment settings so no built-in cron
runs in the Vercel-linked deployment path, and trigger weekly drafts from the UI
button instead.

## Quick start

Requirements for local development: Docker Desktop (or Docker Engine with Compose) and about 4 GB of
free memory. No account or API key is needed for the seeded demo.
Docker is not required for Vercel-only deployment.

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose exec backend python -m app.demo_seed
```

On macOS or Linux, use `cp .env.example .env` for the first command.

Open:

- Analyst console: <http://localhost:3000>
- Interactive API: <http://localhost:8000/docs>
- Health: <http://localhost:8000/health>
- Readiness: <http://localhost:8000/ready>

The seed command is explicit, deterministic, and idempotent. It never runs by
itself and never contacts an external feed. Remove the seeded records or use a
fresh database before evaluating live collection.

Seeded rows remain marked as demo data in PostgreSQL. The console explicitly
labels the corpus as seeded demo, live, mixed, or empty, so a successful HTTP
response can never erase dataset provenance. Demo and live evidence is never
combined for corroboration or campaign edges; in a mixed corpus, operational
analytics and newly generated artifacts use the live partition.

Compose binds both web ports to `127.0.0.1` by default. Administrative API
operations remain disabled until you set `ADMIN_API_KEY`; the demo seed runs
inside the backend container and does not weaken that boundary.

Stop the stack with `docker compose down`. Database data remains in the named
volume; `docker compose down -v` intentionally removes it.

## Enabling live services

| Service | Needed for | Account |
|---|---|---|
| abuse.ch Auth-Key | URLhaus and ThreatFox collection | Free, required for current APIs |
| ArcGIS Location Platform | Optional future premium location services | Browser key optional; the public ArcGIS World Imagery map works without one |
| Google AI Studio | Gemini report/assistant prose | Free-tier backend key, optional |
| OpenRouter | Best-effort cloud model fallback | Free account and backend key, optional; free models have low limits |
| Ollama | Local report/assistant prose | No account, optional local install |
| Feodo Tracker | Feodo collection | None |
| ip-api | Non-commercial demo geolocation | None; HTTP-only free endpoint |
| MITRE ATT&CK | Technique catalog | None |

Use each provider's current account portal for signup, key restrictions,
free-tier limitations, and data-use terms. Three details are easy to miss:

- `ABUSECH_AUTH_KEY` and `GEMINI_API_KEY` are server secrets.
- `OPENROUTER_API_KEY` is also a server secret; `openrouter/free` is a
  best-effort, rate-limited fallback rather than an uptime guarantee.
- `VITE_ARCGIS_API_KEY` is visible in the built browser app by design. Restrict
  it by allowed referrers, service privileges, and expiry in the ArcGIS portal.
- Google's current Gemini terms allow free-tier inputs and outputs to be used
  to improve its products, including human review. Send only public OSINT or
  use the local Ollama option; recheck the terms before deployment.

For an explicit public-OSINT fallback, keep `LLM_PROVIDER=gemini` and set
`LLM_FALLBACK_PROVIDER=openrouter`, `OPENROUTER_API_KEY`, and
`OPENROUTER_MODEL=openrouter/free`. A fallback can improve availability but no
free cloud service can promise that generation will always succeed.

After editing `.env`, rebuild affected services:

```powershell
docker compose up --build -d
```

## Local development

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
$env:DATABASE_URL = "sqlite+aiosqlite:///./threatmesh-dev.sqlite3"
$env:SCHEDULER_ENABLED = "false"
$env:DATA_RETENTION_DAYS = "30"
uvicorn app.main:app --reload
```

SQLite is a convenience path for tests and API development. Use the Compose
PostGIS service to exercise geography indexes and production migrations.

### Frontend deployment on Vercel

From `frontend/`, a Vercel-friendly workflow is:

```powershell
cd frontend
Copy-Item .env.example .env.production
npm ci
npm run build
```

Then create a Vercel project with:

- Framework preset: **Vite**
- Install command: `npm ci`
- Build command: `npm run build`
- Output directory: `dist`

Set `VITE_API_BASE_URL` to your backend origin plus `/api/v1`
(for example, `https://api.example.com/api/v1`) so report generation and all
other API calls reach the backend.

### Backend deployment on Vercel

From `backend/`, create a Vercel project and deploy with:

```powershell
cd backend
vercel
```

Use these required runtime values:

```text
DATABASE_URL=postgresql+asyncpg://...
TRUSTED_HOSTS=<frontend>.vercel.app,.vercel.app
CORS_ORIGINS=https://<frontend>.vercel.app
SCHEDULER_ENABLED=false
EXTERNAL_SCHEDULER_ENABLED=false
AUTO_CREATE_SCHEMA=false
DATA_RETENTION_DAYS=30
```

`backend/vercel.json` already routes all requests to `api/index.py`, so the backend
serves `/api/v1/...` and report generation remains manual (`POST /api/v1/reports/generate`).

You can also deploy both layers in a single command from repository root using the newly added root `vercel.json`:

```powershell
vercel
```

In that mode, Vercel uses the root SPA + function pipeline:

- Frontend built from `frontend/package.json` with output `frontend/dist`
- Backend function served at `/api/*` from `backend/api/index.py`

### Frontend

```powershell
cd frontend
npm ci
Copy-Item .env.example .env
npm run dev
```

The Vite server proxies `/api` to the local FastAPI service. Set
`VITE_DEMO_MODE=true` to force the bundled dataset. When the API is reachable
but empty, the UI shows an empty state rather than silently substituting demo
records.

### Quality checks

```powershell
make lint
make test
```

On Windows without `make`, run the equivalent commands directly:

```powershell
cd backend
python -m ruff check .
python -m ruff format --check .
python -m pytest

cd ..\frontend
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

## Repository map

```text
backend/
  app/
    ingestion/       source-isolated connectors and normalization
    enrichment/      literal-IP geolocation and ASN cache
    attack_mapping/  ATT&CK STIX catalog and reviewed aliases
    clustering/      graph construction and community detection
    scoring/         versioned confidence evidence snapshots
    evidence/        per-IOC provenance and derivation lineage
    detection_rules/ review-required Sigma and Suricata generation
    genai/            evidence-first provider abstraction
    api/              versioned REST and GeoJSON contracts
  alembic/            production schema history
  tests/              network-free behavioral tests
frontend/
  src/                analyst workspaces, map, charts, and API client
docs/                  local learning notes (ignored by Git)
reports/               local report exports (ignored by Git)
rules/                 local detection exports (ignored by Git)
```

## Safety and limitations

- ThreatMesh is passive and defensive. It never scans, probes, or opens an
  ingested IOC.
- IP location is an estimate of network infrastructure, not a person or exact
  physical host. The interface uses illustrative geodesic uncertainty circles;
  their radius is a visual context buffer, not a calibrated error bound.
- Campaigns are correlation candidates, not actor attribution.
- Confidence is a queue-prioritization heuristic, not a probability or verdict.
- Each completed score stores its formula version, evaluation time, and exact
  component points. New feed observations remain analysis-pending rather than
  presenting an upstream feed hint as a ThreatMesh score.
- Generated rules and prose require analyst review and are never deployed
  automatically.
- Assistant citation validation proves that a displayed evidence ID belonged to
  that request's retrieved fact set; it does not prove that every generated
  sentence is semantically supported.
- The free ip-api service is HTTP-only and non-commercial. Use a licensed HTTPS
  provider or offline database for commercial or higher-assurance deployment.

Read the [security policy](SECURITY.md) before exposing an instance outside a
trusted development network.

## Deliberate scope boundaries

- PhishTank and NVD are not connected in this release. PhishTank was optional
  in the brief; NVD is deferred because the primary feeds do not provide a
  reliable IOC-to-CVE relationship and keyword inference would be misleading.
- A country choropleth is deferred until a reviewed country-polygon dataset is
  introduced. Point counts are not mislabeled as polygon analysis. The bounded
  ArcGIS flat view provides clusters, density heatmaps, and uncertainty radii;
  the non-WebGL raster fallback aggregates overlapping markers.
- Time filtering uses a transparent observation-window control instead of the
  TimeSlider widget deprecated in ArcGIS Maps SDK 5.x.
- ThreatMesh exports detection/report artifacts but never commits them or
  changes Git history automatically. Analyst review remains an explicit step.

## Lessons learned

The hardest part was not drawing a map or calling a model; it was preserving
meaning while data crossed systems. Feed authentication and schemas change,
IP-and-port observations need a stricter identity than bare strings, estimated
locations need visible uncertainty, and generated prose needs an evidence
boundary. Keeping those concerns explicit produced a smaller but more honest
system: deterministic analysis remains testable, external integrations can
fail independently, and every analyst-facing artifact retains provenance and a
review step.

## Contributing and license

Contributions are welcome under the guidelines in [CONTRIBUTING.md](CONTRIBUTING.md).
ThreatMesh is released under the [MIT License](LICENSE).

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
ThreatMesh uses ATT&CK data under MITRE's published terms and is not endorsed
by MITRE. Third-party feed and platform data remains subject to each provider's
terms.
