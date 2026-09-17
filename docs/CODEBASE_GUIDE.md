# ThreatMesh Codebase Guide

This guide explains the repository in simple English. Read
[PROJECT_GUIDE.md](PROJECT_GUIDE.md) first for the product story, then use this
file to understand where each behavior is implemented.

## 1. The simplest mental model

ThreatMesh has four main layers:

```text
External sources
      |
      v
Backend services -----> PostgreSQL/PostGIS
      |
      v
FastAPI routes
      |
      v
Typed frontend client -> React pages and components
```

The backend owns truth. It collects, validates, stores, and analyzes evidence.
The API exposes limited, typed views of that truth. The frontend presents those
views and never calculates security conclusions by itself.

Dependencies should move inward in this order:

```text
route -> service -> model/database
page -> hook -> API client -> route
```

A feed parser should not import a React concept. A React page should not know how
SQL tables are joined. This separation keeps tests and changes manageable.

## 2. Repository structure

```text
ThreatMesh/
├── backend/             FastAPI, analysis services, database models, tests
├── frontend/            React/TypeScript analyst console
├── deploy/gcp/          GCP runtime configuration examples
├── docs/                Design, setup, decisions, and these guides
├── .github/             CI, dependency updates, and issue templates
├── docker-compose.yml   Complete local stack
├── firebase.json        Optional static frontend hosting configuration
├── vercel.json          Combined Vercel build/routing configuration
└── README.md            Public project landing page and quick start
```

## 3. Important runtime flows

### Feed-to-dashboard flow

```text
connector.fetch_batch()
  -> IngestionService.sync_all()
  -> normalized IOC rows + FeedRun telemetry
  -> EnrichmentService.enrich_pending()
  -> PipelineService.run_analysis()
  -> confidence + ATT&CK + campaigns + rules
  -> FastAPI route
  -> threatApi normalizer
  -> React Query hook
  -> page/component
```

### Ask ThreatMesh flow

```text
AssistantPage
  -> threatApi.ask()
  -> POST /assistant/ask
  -> RetrievalQAService retrieves bounded facts
  -> provider writes structured answer
  -> server validates citation IDs
  -> UI renders answer and exact evidence links
```

### On-demand report flow

```text
ReportsPage button
  -> threatApi.generateWeeklyReport()
  -> POST /reports/generate
  -> retention cleanup
  -> previous complete weekly period
  -> ReportService.collect_facts()
  -> Gemini/Ollama/static provider
  -> idempotent Report row
  -> report list refetch
```

### Bulk investigation flow

```text
InvestigationPage input
  -> POST /iocs/investigate
  -> refang + infer type + canonicalize
  -> exact retained-corpus lookup
  -> matched / unmatched / invalid groups
  -> optional STIX, CSV, or plain blocklist download
```

## 4. Root files

| File | Purpose |
|---|---|
| `.editorconfig` | Gives editors the same indentation, line-ending, and final-newline rules. |
| `.env.example` | Documents root environment variables for Compose, the API, feeds, AI, scheduling, and the frontend. It contains placeholders, not real secrets. |
| `.gitattributes` | Makes Git handle text and line endings consistently. |
| `.gitignore` | Prevents secrets, local databases, caches, build output, exported rules/reports, and editor files from being committed. |
| `CONTRIBUTING.md` | Explains development expectations, checks, and contribution workflow. |
| `LICENSE` | MIT license for the project's own code. External data keeps its own terms. |
| `Makefile` | Short commands for linting, testing, and common developer work. |
| `README.md` | Public overview, quick start, architecture, configuration, limitations, and deployment entry points. |
| `SECURITY.md` | Defines supported security posture, secret handling, deployment warnings, and vulnerability reporting. |
| `docker-compose.yml` | Starts PostGIS, the backend, the frontend, migrations, and optional coordinator in a repeatable local environment. |
| `firebase.json` | Configuration for serving the built single-page frontend from Firebase Hosting. |
| `vercel.json` | Root Vercel configuration that builds the Vite frontend and routes API requests to the Python function. |

## 5. GitHub automation

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Runs backend lint/format/tests and frontend format/lint/typecheck/tests/build on pushes and pull requests. |
| `.github/dependabot.yml` | Requests dependency update pull requests for supported package ecosystems. |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Asks bug reporters for reproducible technical information. |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Structures feature proposals around value, scope, and security impact. |

## 6. Backend entry and foundation files

| File | Purpose |
|---|---|
| `backend/app/__init__.py` | Marks `app` as a Python package. |
| `backend/app/main.py` | Builds the FastAPI application, installs middleware and error handlers, attaches routes, manages database/scheduler lifespan, and provides health/readiness endpoints. Start here when learning backend startup. |
| `backend/app/config.py` | Defines all environment-backed settings with Pydantic validation. It rejects unsafe bounds and conflicting scheduler ownership early. |
| `backend/app/database.py` | Creates the asynchronous SQLAlchemy engine/session factory and normalizes hosted PostgreSQL URLs such as Neon connection strings. |
| `backend/app/errors.py` | Defines the application error type and converts application, validation, and unexpected errors into consistent JSON responses. |
| `backend/app/logging.py` | Configures local or JSON logging and adds structured fields useful in hosted logs. |
| `backend/app/middleware.py` | Adds request IDs, security headers, processing time, trusted request behavior, and in-memory public/AI rate limiting. |
| `backend/app/analysis_scope.py` | Chooses live, demo, mixed-display, or empty scope. Operational analysis is live-first and never mixes demo and live evidence. |
| `backend/app/pipeline.py` | Orchestrates deterministic analysis in the correct order: scoring, ATT&CK mapping, clustering, and rule generation. |
| `backend/app/maintenance.py` | Deletes evidence, cache, feed telemetry, and reports older than the configured retention period in a controlled transaction. |
| `backend/app/demo_seed.py` | Creates a deterministic, clearly marked demo dataset and sample artifacts. It is explicit and idempotent; it never runs automatically. |
| `backend/app/export_artifacts.py` | Exports stored rules and reports to local folders with atomic writes and no overwrite by default. This preserves analyst edits. |
| `backend/app/report_scheduling.py` | Stores cadence and calculates complete weekly/monthly periods and next-run times. It supports persistent deployments even though the public Vercel UI uses on-demand reports. |
| `backend/app/scheduler.py` | Owns APScheduler jobs for embedded deployments and safely updates scheduled report cadence. |
| `backend/app/jobs.py` | Implements the external one-shot coordinator for platforms such as Cloud Run Jobs. A PostgreSQL advisory lock prevents two coordinators from owning the pipeline together. |

## 7. Database model files

| File | Purpose |
|---|---|
| `backend/app/models/__init__.py` | Re-exports model classes so other modules can import them from one stable place. |
| `backend/app/models/base.py` | Defines the SQLAlchemy declarative base, UTC timestamp helper, and shared created/updated columns. |
| `backend/app/models/enums.py` | Defines controlled values for IOC type, rule type, feed-run status, and report cadence. |
| `backend/app/models/entities.py` | Defines every database table and relationship: `IOC`, `Campaign`, `AttackTechnique`, `DetectionRule`, `Report`, `ReportSchedule`, `GeoCache`, and `FeedRun`. It also provides a geography type that compiles correctly for PostgreSQL and tests. |

### Main data entities

| Entity | Meaning |
|---|---|
| `IOC` | One normalized source observation, its context, score snapshot, coordinates, campaign membership, and safe raw evidence. |
| `Campaign` | A calculated community of related IOCs. It is a candidate, not attribution. |
| `AttackTechnique` | A versioned MITRE ATT&CK technique record. |
| `DetectionRule` | A stored Sigma or Suricata draft with identity, provenance, and review state. |
| `Report` | A reporting-period snapshot, deterministic facts, provider metadata, and generated/analyst narrative. |
| `ReportSchedule` | Persisted weekly/monthly preference for scheduler-capable deployments. |
| `GeoCache` | Cached successful or failed IP/ASN location lookup. |
| `FeedRun` | Operational record of a collection attempt and its row counts/error. |

## 8. Ingestion files

| File | Purpose |
|---|---|
| `backend/app/ingestion/__init__.py` | Exposes the ingestion service and connector types. |
| `backend/app/ingestion/base.py` | Contains the shared feed contract, normalized IOC schema, safe timestamp parsing, IOC type inference, URL/indicator canonicalization, IP:port handling, bounded HTTP download, redirects, retry rules, and response-size enforcement. This is the ingestion trust boundary. |
| `backend/app/ingestion/urlhaus.py` | Converts URLhaus results into normalized URL observations and preserves source context. |
| `backend/app/ingestion/threatfox.py` | Parses the wider ThreatFox IOC formats, malware names, confidence hints, timestamps, and ports. |
| `backend/app/ingestion/feodo.py` | Parses Feodo Tracker botnet C2 rows, especially IP/port observations. |
| `backend/app/ingestion/service.py` | Runs selected connectors, records feed telemetry, collapses duplicates, performs idempotent upserts, preserves provenance, and invalidates analysis snapshots only when evidence changes. |

## 9. Enrichment, scoring, ATT&CK, clustering, and rules

### Enrichment

| File | Purpose |
|---|---|
| `backend/app/enrichment/__init__.py` | Exposes enrichment services. |
| `backend/app/enrichment/geolocation.py` | Extracts literal public IPs, paces `ip-api` requests, caches positive/negative results, and stores country/city/ASN/coordinates. It intentionally does not resolve domain names. |

### Confidence

| File | Purpose |
|---|---|
| `backend/app/scoring/__init__.py` | Exposes scoring functions and service. |
| `backend/app/scoring/confidence.py` | Calculates the bounded, versioned score and exact source/corroboration/recency/context components, then persists one consistent scoring timestamp across a batch. |

### MITRE ATT&CK

| File | Purpose |
|---|---|
| `backend/app/attack_mapping/__init__.py` | Exposes mapping and synchronization functions. |
| `backend/app/attack_mapping/catalog.py` | Contains the reviewed malware-family aliases and technique relationships used by analysis. |
| `backend/app/attack_mapping/service.py` | Applies curated mappings to in-scope IOCs and maintains technique relationships. |
| `backend/app/attack_mapping/sync.py` | Downloads a pinned official ATT&CK STIX bundle with size/shape validation and updates the local technique catalog. It can also run as a command. |

### Candidate campaigns

| File | Purpose |
|---|---|
| `backend/app/clustering/__init__.py` | Exposes the clustering service. |
| `backend/app/clustering/service.py` | Builds evidence-weighted IOC graphs, runs deterministic Louvain communities, rejects invalid/single-node groups, and persists campaign membership and summaries. |

### Detection engineering

| File | Purpose |
|---|---|
| `backend/app/detection_rules/__init__.py` | Exposes generators, service, and artifact naming. |
| `backend/app/detection_rules/generator.py` | Builds stable Sigma/Suricata text, IDs, SIDs, filenames, confidence labels, references, and safe escaping for supported IOC types. |
| `backend/app/detection_rules/service.py` | Chooses eligible high-confidence evidence, creates or updates drafts, and removes stale generated candidates from the active scope. |

## 10. Evidence and generative-AI files

### Evidence

| File | Purpose |
|---|---|
| `backend/app/evidence/__init__.py` | Exposes lineage construction. |
| `backend/app/evidence/lineage.py` | Reconstructs the audit story for one IOC: source observations, payload hash/fields, score components, enrichment, ATT&CK mapping, campaign membership, rules, report mentions, and limitations. |

### Generative AI

| File | Purpose |
|---|---|
| `backend/app/genai/__init__.py` | Gives routes and services a compact import surface. |
| `backend/app/genai/providers.py` | Defines one provider interface and Gemini, Ollama, and static implementations. It handles timeouts, bounded retries, response validation, and actionable configuration errors. |
| `backend/app/genai/prompts.py` | Stores the system instructions that restrict answers and reports to supplied facts and structured output. Keeping prompts separate makes review easier. |
| `backend/app/genai/qa.py` | Performs constrained retrieval, creates compact evidence, calls the provider, parses structured output, and validates citation identities and order. |
| `backend/app/genai/reports.py` | Collects exact reporting aggregates and bounded examples, prevents empty-data generation, calls the provider, and saves an idempotent report snapshot. |

## 11. API files

| File | Purpose |
|---|---|
| `backend/app/api/__init__.py` | Marks the API package. |
| `backend/app/api/dependencies.py` | Provides database sessions/settings, constant-time administrator-key checks, and the separate AI request limiter. |
| `backend/app/api/router.py` | Mounts all versioned route modules in one place. |
| `backend/app/api/schemas.py` | Defines request and response contracts for GeoJSON, investigation, lineage, campaigns, statistics, techniques, rules, reports, schedules, operations, and assistant answers. |
| `backend/app/api/routes/__init__.py` | Marks the route package. |
| `backend/app/api/routes/iocs.py` | Lists/filter IOCs as GeoJSON, returns detail/lineage, performs bulk exact investigation, refangs supported input, checks blocklist safety, and exports STIX 2.1. |
| `backend/app/api/routes/stats.py` | Calculates overview totals, trends, country/family buckets, technique trends, provenance mode, and feed-health state. |
| `backend/app/api/routes/campaigns.py` | Lists candidate campaigns and returns campaign members. |
| `backend/app/api/routes/techniques.py` | Lists ATT&CK techniques with current in-scope observation trends. |
| `backend/app/api/routes/rules.py` | Lists, requests generation of, and downloads review-required rules. Mutating generation is admin-protected. |
| `backend/app/api/routes/reports.py` | Lists/downloads reports, creates the on-demand previous-week report, and retains schedule endpoints for persistent deployments. |
| `backend/app/api/routes/assistant.py` | Accepts a bounded question and returns the grounded answer, retrieval metadata, and validated citations. |
| `backend/app/api/routes/operations.py` | Exposes admin-only feed, enrichment, and analysis actions plus public feed-run status. It blocks local mutation if an external coordinator owns the pipeline. |

## 12. Database migrations

| File | Purpose |
|---|---|
| `backend/alembic.ini` | Alembic command configuration. |
| `backend/alembic/env.py` | Connects Alembic to application metadata and the configured database. |
| `backend/alembic/script.py.mako` | Template for future migration files. |
| `backend/alembic/versions/0001_initial_schema.py` | Creates the initial entities, indexes, relationships, and PostGIS support. |
| `backend/alembic/versions/0002_report_scheduling.py` | Adds cadence and persisted schedule support. |
| `backend/alembic/versions/0003_evidence_lineage.py` | Adds the fields and indexes needed for stronger provenance and confidence evidence. |
| `backend/alembic/versions/0004_report_idempotency.py` | Adds stable report schedule/evidence keys so the same period is not generated twice. |

Never edit a migration that may already have run in another database. Add a new
migration instead.

## 13. Backend packaging and deployment files

| File | Purpose |
|---|---|
| `backend/pyproject.toml` | Python package metadata, runtime/dev dependencies, Pytest settings, Ruff rules, and formatting policy. This is the main Python dependency source. |
| `backend/requirements.txt` | Flat dependency list used by serverless deployment tooling that expects this filename. Keep it aligned with `pyproject.toml`. |
| `backend/.env.example` | Backend-only environment examples for running outside root Compose. |
| `backend/.gitignore` | Ignores Python caches, environments, local databases, secrets, and build/test output inside the backend. |
| `backend/.dockerignore` | Keeps unnecessary files out of the backend Docker build context. |
| `backend/.gcloudignore` | Keeps local and secret material out of Google Cloud builds. |
| `backend/Dockerfile` | Builds the production Python API image. |
| `backend/README.md` | Backend-specific development notes and commands. |
| `backend/api/index.py` | Vercel Python function entry point that exposes the FastAPI application. |
| `backend/vercel.json` | Vercel route and function configuration when the backend is deployed as its own project. |

## 14. Backend tests

The test suite avoids live internet calls. Fake providers and responses make results
repeatable.

| File | Main behaviors covered |
|---|---|
| `backend/tests/__init__.py` | Marks the test package. |
| `backend/tests/conftest.py` | Creates isolated settings, an async test database, FastAPI client, schema, and cleanup fixtures. |
| `backend/tests/factories.py` | Creates valid IOC test objects with sensible defaults. |
| `backend/tests/test_ingestion.py` | Feed parsing, timestamp safety, IPv4/IPv6 ports, URL normalization, auth redirects, response bounds, idempotent upserts, score invalidation, rollback counts, and feed telemetry. |
| `backend/tests/test_enrichment.py` | Literal-IP-only lookup, per-batch reuse, and expiring negative cache behavior. |
| `backend/tests/test_analysis.py` | Settings bounds, question periods, citation parsing, ATT&CK STIX filtering, confidence, clustering rules/determinism, and safe Sigma/Suricata generation. |
| `backend/tests/test_provenance_scope.py` | Strict demo/live separation across scores, campaigns, rules, reports, QA, stats, and feed health. |
| `backend/tests/test_evidence_lineage.py` | Exact score components, shared scoring time, source/port/scope boundaries, derivation links, and pending-score representation. |
| `backend/tests/test_demo_and_api.py` | Seed idempotency, API contracts, IOC identity, investigation/export, refanging, corpus modes, errors, retrieval, citation validation, report facts, rule generation, and disabled-AI messages. |
| `backend/tests/test_report_scheduling.py` | Complete calendar windows, schedule authorization, on-demand generation/retention, concurrency, embedded/external scheduling, and report idempotency. |
| `backend/tests/test_jobs.py` | External coordinator timing, lock ownership, shared pipeline, and due-report stage. |
| `backend/tests/test_genai_providers.py` | Gemini retry and safe service-error behavior without a live model call. |
| `backend/tests/test_export_and_attack_sync.py` | Non-destructive artifact export and bounded/validated ATT&CK download. |
| `backend/tests/test_migrations.py` | Fresh and legacy schema upgrades, provenance fields, score invalidation, and report keys. |
| `backend/tests/test_postgis_compilation.py` | Safe bound parameters and correct text conversion for PostGIS geography SQL. |

## 15. Frontend startup, routing, and data files

| File | Purpose |
|---|---|
| `frontend/src/main.tsx` | Browser entry point. It creates React Query and router providers, imports global styles, and renders the app. |
| `frontend/src/App.tsx` | Defines lazy-loaded routes for overview, investigate, indicators, campaigns, ATT&CK, rules, reports, assistant, and settings inside the shared shell. |
| `frontend/src/types.ts` | Central TypeScript contracts used by pages, components, hooks, and the API adapter. |
| `frontend/src/api/client.ts` | The frontend boundary to the backend. It sends requests, normalizes snake/camel case and uncertain payloads, tracks live/demo mode, applies explicit demo fallback, and exposes typed methods. |
| `frontend/src/hooks/useThreatData.ts` | Small React Query hooks and cache keys for indicators, lineage, campaigns, techniques, reports, rules, summary, and feed status. |
| `frontend/src/data/mockData.ts` | Deterministic, clearly synthetic UI data used only when demo mode/fallback policy allows it. |

## 16. Frontend layout and shared components

| File | Purpose |
|---|---|
| `frontend/src/components/AppShell.tsx` | Navigation, responsive layout, corpus/API mode banners, page title, and route outlet. |
| `frontend/src/components/Logo.tsx` | Reusable ThreatMesh brand mark and text. |
| `frontend/src/components/UI.tsx` | Shared badges, confidence display, KPI cards, headings, empty states, copy button, loaders, and skeleton rows. |
| `frontend/src/components/Charts.tsx` | Lightweight SVG sparkline, area trend, and donut visualizations without another chart framework. |
| `frontend/src/components/IndicatorDetail.tsx` | Detailed IOC drawer/view including identity, context, confidence components, provenance, derived artifacts, and limitations. |
| `frontend/src/components/CampaignGraph.tsx` | Draws the selected campaign's member relationship graph. |
| `frontend/src/components/OperationsCenter.tsx` | Admin-key modal and buttons for feed sync, enrichment, and analysis; the key is held only for the request and not persisted. |
| `frontend/src/components/OperationsCenter.css` | Focused styling for operation status and authorization controls. |

## 17. Frontend map files

| File | Purpose |
|---|---|
| `frontend/src/components/ThreatMap.tsx` | Main ArcGIS WebGL map. Builds the client-side layer, popups, family colors, cluster/heatmap/location-context renderers, time filter, viewport constraints, and fallback handoff. |
| `frontend/src/components/ArcGisRasterMap.tsx` | Canvas/raster ArcGIS fallback for machines without WebGL. Loads public Esri tiles, wraps longitude, constrains zoom/center, aggregates markers, and supports selection. |
| `frontend/src/components/mapViewport.ts` | Pure math for minimum flat-map zoom, safe Web Mercator extent, and center constraints so zooming out does not reveal empty black space. |
| `frontend/src/components/mapVisuals.ts` | Stable palette and deterministic malware-family color selection. |

## 18. Frontend pages

| File | Purpose |
|---|---|
| `frontend/src/pages/DashboardPage.tsx` | Overview KPIs, operations access, map, filters, trends, distributions, and feed-health summary. |
| `frontend/src/pages/InvestigationPage.tsx` | Bulk observable input, validation, matched/unmatched/invalid results, safe blocklist warnings, and STIX/CSV/text exports. |
| `frontend/src/pages/InvestigationPage.css` | Workbench-specific grid, result, status, and export styling. |
| `frontend/src/pages/IndicatorsPage.tsx` | Paginated/searchable/filterable indicator list and detail selection. |
| `frontend/src/pages/CampaignsPage.tsx` | Candidate campaign list, confidence/context summary, graph, and member pivots. |
| `frontend/src/pages/AttackPage.tsx` | ATT&CK technique catalog and trend view linked to supporting observations. |
| `frontend/src/pages/RulesPage.tsx` | Rule library, source/review labels, content preview, and downloads. |
| `frontend/src/pages/ReportsPage.tsx` | On-demand weekly report action, report list/detail retrieval, grounded narrative display, citations/pivots, and Markdown export. |
| `frontend/src/pages/AssistantPage.tsx` | Ask ThreatMesh conversation UI, suggestion prompts, retrieval/citation metadata, evidence links, errors, and empty states. |
| `frontend/src/pages/SettingsPage.tsx` | Explains runtime mode, privacy/provider choices, required accounts, data boundaries, and configuration guidance. It does not expose server secrets. |

## 19. Frontend utilities and styling

| File | Purpose |
|---|---|
| `frontend/src/styles/global.css` | Main design system and responsive styles: colors, typography, layout, panels, map, tables, reports, assistant, modals, and accessibility states. |
| `frontend/src/utils/format.ts` | Date, UTC, number, confidence-band, relative-time, range, and safe browser-download helpers. |
| `frontend/src/utils/csv.ts` | Escapes cells and builds valid CSV, including protection against malformed quoting/newlines. |
| `frontend/src/utils/artifacts.ts` | Adds an unmistakable synthetic-demo header to downloaded demo artifacts. |

## 20. Frontend tests

| File | Main behaviors covered |
|---|---|
| `frontend/src/test/setup.ts` | Installs DOM matchers and stable browser mocks for Vitest. |
| `frontend/src/api/client.test.ts` | URL/query construction, normalization, error handling, demo fallback, investigation/export, and assistant/report contracts. |
| `frontend/src/data/mockData.test.ts` | Demo data consistency and clear synthetic provenance. |
| `frontend/src/components/ArcGisRasterMap.test.tsx` | Raster fallback rendering, attribution, controls, marker interaction, and viewport behavior. |
| `frontend/src/components/ThreatMap.test.tsx` | WebGL loading/failure behavior, renderer controls, filters, fallback, and user-facing labels. |
| `frontend/src/components/mapViewport.test.ts` | Minimum zoom and constrained center calculations that prevent blank world-map space. |
| `frontend/src/components/IndicatorDetail.test.tsx` | Evidence sections, confidence state, links, and missing-data handling. |
| `frontend/src/pages/AssistantPage.test.tsx` | Questions, suggestions, citations, errors, disabled provider, and no black-screen regressions. |
| `frontend/src/pages/AttackPage.test.tsx` | ATT&CK loading, technique detail, filtering, and evidence labels. |
| `frontend/src/pages/CampaignsPage.test.tsx` | Campaign selection, graph/detail data, and empty/error states. |
| `frontend/src/pages/ReportsPage.test.tsx` | On-demand generation, loading/errors, report detail, grounding labels, and download behavior. |
| `frontend/src/pages/RulesPage.test.tsx` | Rule listing, review/provenance labels, preview, and export. |
| `frontend/src/utils/artifacts.test.ts` | Synthetic download labeling. |
| `frontend/src/utils/csv.test.ts` | CSV escaping and row creation. |
| `frontend/src/utils/format.test.ts` | UTC/date/range/confidence/download formatting. |

## 21. Frontend build and deployment files

| File | Purpose |
|---|---|
| `frontend/package.json` | Frontend dependencies and scripts for development, formatting, linting, type checking, tests, and production build. |
| `frontend/package-lock.json` | Exact resolved npm dependency graph for reproducible installs. It is generated; do not edit it by hand. |
| `frontend/tsconfig.json` | Shared TypeScript project references. |
| `frontend/tsconfig.app.json` | Strict browser application compiler settings. |
| `frontend/tsconfig.node.json` | TypeScript settings for Vite/Node configuration code. |
| `frontend/vite.config.ts` | Vite plugins, local API proxy, test environment, and build behavior. |
| `frontend/eslint.config.js` | JavaScript/TypeScript/React lint rules. |
| `frontend/index.html` | HTML shell where Vite mounts the application. |
| `frontend/public/favicon.svg` | Browser tab icon. |
| `frontend/.env.example` | Public frontend settings only: API base URL, optional restricted ArcGIS browser key, and explicit demo mode. |
| `frontend/.prettierignore` | Files excluded from formatting checks. |
| `frontend/.dockerignore` | Reduces the frontend Docker build context. |
| `frontend/Dockerfile` | Builds the Vite app, then serves it from Nginx. |
| `frontend/nginx/default.conf` | SPA routing, API proxy, compression/cache behavior, and Nginx server rules. |
| `frontend/nginx/security-headers.conf` | Browser security headers, including the policy needed by ArcGIS workers/assets. |
| `frontend/vercel.json` | Vercel static build and SPA rewrite settings for a separate frontend project. |

## 22. Deployment files

| File | Purpose |
|---|---|
| `deploy/gcp/runtime.env.yaml.example` | Non-secret Cloud Run runtime settings. Copy it and supply real environment-specific values without committing them. |
| `deploy/gcp/artifact-cleanup-policy.json` | Artifact Registry policy that removes old untagged images to control storage cost. |

The repository supports two deployment styles:

- **Vercel:** best for the portfolio UI and request-driven API. Use on-demand
  reports and disable embedded scheduling.
- **GCP persistent/coordinator deployment:** better when feed synchronization and
  background analysis must run reliably on a clock.

Never commit provider keys. Use Vercel environment variables or GCP Secret Manager.

## 23. Documentation files

| File | Purpose |
|---|---|
| `docs/PROJECT_GUIDE.md` | Plain-English project story, research, architecture, value, limitations, roadmap, and interview preparation. |
| `docs/CODEBASE_GUIDE.md` | This file-by-file code map. |
| `docs/architecture.md` | Formal component boundaries, trust zones, and deployment topology. |
| `docs/methodology.md` | Exact analytical methods, confidence interpretation, campaign logic, and evidence constraints. |
| `docs/operations.md` | Operator procedures for startup, migrations, jobs, backup/restore, monitoring, and incident handling. |
| `docs/api-accounts.md` | Signup and safe configuration notes for abuse.ch, Gemini, ArcGIS, Ollama, and enrichment services. |
| `docs/product-research.md` | Product/standards research behind investigation, STIX export, and deferred feature choices. |
| `docs/assets/dashboard.png` | README screenshot. It is a binary asset, not source code. |
| `docs/decisions/0001-deterministic-analysis-before-generation.md` | Records why deterministic security logic must run before AI prose. |
| `docs/decisions/0002-geolocation-is-an-estimate.md` | Records why approximate network location is shown with explicit uncertainty. |
| `docs/decisions/0003-separate-demo-and-live-analysis.md` | Records why synthetic and live evidence must never reinforce each other. |
| `docs/decisions/0004-validate-assistant-evidence-identities.md` | Records why assistant citations are checked against a server-built allow-list. |

## 24. Where to make a change

| Desired change | First files to inspect |
|---|---|
| Add a feed | `ingestion/base.py`, a new connector, `ingestion/service.py`, ingestion tests, settings |
| Change confidence | `scoring/confidence.py`, methodology, lineage schemas/UI, analysis/evidence tests |
| Add an IOC field | model, new Alembic migration, API schema/route, client normalizer, TypeScript type, UI, tests |
| Add an API route | route module, `api/router.py` if new, schemas, backend tests, client method, hook/page |
| Change clustering | `clustering/service.py`, methodology, campaign API/UI, analysis tests |
| Add a provider | `genai/providers.py`, configuration, provider tests, account docs |
| Change assistant retrieval | `genai/qa.py`, prompt, assistant schema/client/page, retrieval and citation tests |
| Change reports | `genai/reports.py`, report route, client/page, scheduling and page tests |
| Change the map | `ThreatMap.tsx`, `ArcGisRasterMap.tsx`, viewport/visual helpers, both map test suites |
| Add a page | new page, route in `App.tsx`, navigation in `AppShell.tsx`, hook/client methods, tests/styles |
| Change database schema | entity, new Alembic revision, schemas/services, migration test |

## 25. Rules for safe development

1. Keep secrets in local/deployment environment settings only.
2. Add a migration for schema changes; do not rely on `create_all` in production.
3. Keep source parsing isolated by connector.
4. Preserve observable type and port in identity decisions.
5. Never mix demo evidence into live analysis.
6. Put security decisions in deterministic code, not prompts or frontend logic.
7. Return typed API errors; do not hide a live failure by silently showing demo data.
8. Label generated artifacts as review-required.
9. Update the method/design documentation when changing an analytical rule.
10. Test the boundary that could mislead an analyst, not only the happy path.

## 26. How to verify a change

Backend:

```powershell
cd backend
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

Frontend:

```powershell
cd frontend
npm run format:check
npm run lint
npm run typecheck
npm test -- --run
npm run build
```

Then run the application and manually test the exact analyst workflow you changed.
For a cross-layer change, verify the API response in `/docs` before debugging the
React component.

## 27. Suggested reading order for an interview

If you have one hour:

1. `PROJECT_GUIDE.md` sections 1–16.
2. `README.md` architecture and limitations.
3. `backend/app/pipeline.py` and `analysis_scope.py`.
4. `backend/app/ingestion/base.py` and `ingestion/service.py`.
5. `backend/app/scoring/confidence.py`.
6. `backend/app/genai/qa.py` citation validation.
7. `backend/app/evidence/lineage.py`.
8. `frontend/src/api/client.ts`, `useThreatData.ts`, and one page.
9. The tests for the feature you plan to demonstrate.

If an interviewer asks about a detail you do not remember, explain the invariant
instead of inventing an answer. For example: “I would confirm the exact threshold
in the versioned confidence module, but the design guarantees a bounded component
breakdown stored with the score.” That is a professional answer.
