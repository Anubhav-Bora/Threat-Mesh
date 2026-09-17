# ThreatMesh Project Guide and Interview Handbook

## Project title

**ThreatMesh: An Evidence-Grounded Cyber Threat Intelligence and Investigation Platform**

## The project in one sentence

ThreatMesh collects public cyber-threat indicators, turns them into traceable and
prioritized evidence, and gives an analyst one place to investigate indicators,
view infrastructure on a map, study possible campaigns, create detection content,
and ask evidence-backed questions.

## A 30-second interview answer

> ThreatMesh is a self-hosted cyber-threat intelligence platform built with
> FastAPI, PostgreSQL/PostGIS, React, and ArcGIS. It passively collects indicators
> from URLhaus, ThreatFox, and Feodo Tracker, normalizes and enriches them, scores
> confidence with an explainable formula, maps malware to MITRE ATT&CK, and uses
> graph community detection to suggest related infrastructure. Analysts can run
> bulk investigations, export STIX 2.1, inspect evidence lineage, create
> review-required Sigma and Suricata rules, and use an AI assistant that can cite
> only records retrieved by the server. The important security decisions remain
> deterministic; Gemini or Ollama is used only to write grounded prose.

## 1. Problem statement

Public threat intelligence is useful but fragmented. Different feeds use different
schemas, repeat the same indicator, omit context, and change over time. A raw list
of thousands of IP addresses, URLs, domains, and hashes does not directly tell a
security analyst:

- which observations deserve attention first;
- where an item came from and whether another source confirmed it;
- which malware or ATT&CK behavior may be related;
- which items may belong to the same infrastructure campaign;
- what detection content can be drafted safely; or
- whether an AI-generated explanation is supported by stored evidence.

ThreatMesh solves this translation problem. It changes disconnected public feed
records into a small, inspectable intelligence workflow. It is deliberately a
decision-support system, not an autonomous blocking system.

## 2. Why the problem matters

Security teams can receive more observations than they can manually review. Simple
feed aggregation can make that problem worse because it increases volume without
increasing understanding. ThreatMesh adds value after collection:

1. It normalizes records so they can be compared.
2. It keeps source and raw-payload evidence so conclusions can be checked.
3. It calculates a transparent priority score rather than hiding logic in an AI
   response.
4. It shows relationships between indicators.
5. It creates portable, review-required outputs for other security tools.

This is useful for a SOC analyst, threat-intelligence analyst, detection engineer,
security student, or small team that wants a low-cost CTI laboratory.

## 3. Background and research

ThreatMesh was designed from the supplied project specification and refined using
official standards, primary documentation, and one algorithm paper. It does not
claim to reproduce a single research paper.

### Standards and design references

- [STIX 2.1](https://www.oasis-open.org/standard/stix-version-2-1/) is the OASIS
  standard used for portable indicator export. ThreatMesh creates deterministic
  STIX indicator identities so repeated exports can be deduplicated downstream.
- [MITRE ATT&CK design and philosophy](https://attack.mitre.org/resources/learn-more-about-attack/)
  informed the use of ATT&CK as a behavior vocabulary. ThreatMesh keeps its
  malware-family mappings curated and visible; it does not infer actor attribution.
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
  informed the portable log-detection templates.
- [Suricata rule documentation](https://docs.suricata.io/en/suricata-8.0.0/rules/intro.html)
  informed the network-rule structure and escaping requirements.
- [URLhaus and ThreatFox](https://auth.abuse.ch/) plus
  [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) are the public OSINT
  sources used by the live ingestion layer.

### Algorithm reference

Campaign candidates use the Louvain community-detection approach described by
Blondel, Guillaume, Lambiotte, and Lefebvre in
[“Fast unfolding of communities in large networks”](https://arxiv.org/abs/0803.0476).
In ThreatMesh, indicators are graph nodes. Strong shared evidence, such as malware
family and infrastructure context, creates edges. Louvain then finds dense
communities. The result is called a **candidate campaign**, not a confirmed threat
actor or operation.

### Important research lesson

A standard or algorithm does not make a result automatically correct. STIX makes
data portable, ATT&CK makes behavior names consistent, and Louvain finds graph
communities. An analyst must still decide what the evidence means. The interface
therefore exposes provenance, limitations, confidence components, and review
warnings.

## 4. Proposed solution

ThreatMesh uses a layered pipeline:

```text
Public feeds
    |
    v
Fetch safely -> parse -> validate -> normalize -> deduplicate
    |
    v
PostgreSQL/PostGIS evidence store
    |
    +--> IP/ASN geolocation cache
    +--> explainable confidence scoring
    +--> curated MITRE ATT&CK mapping
    +--> graph-based campaign candidates
    +--> review-required detection rules
    |
    v
FastAPI contracts and evidence retrieval
    |
    +--> React/ArcGIS analyst console
    +--> bulk investigation and STIX/CSV/blocklist export
    +--> on-demand grounded report
    +--> retrieval-first Ask ThreatMesh assistant
```

The central design rule is: **compute facts first, use AI second**.

Gemini or Ollama can phrase an answer or report. It cannot edit a confidence score,
create campaign membership, assign ATT&CK techniques, deploy a rule, or decide to
block an indicator.

## 5. What, why, and how

| Capability | What it does | Why it exists | How it works |
|---|---|---|---|
| Feed ingestion | Collects URL, domain, IP, IP:port, and hash observations | Public feeds have different formats | One bounded connector per source parses into a common model |
| Canonicalization | Produces a stable identity for an observable | Equivalent strings should not become unrelated records | URL, host, type, and port-aware normalization runs before upsert |
| Provenance | Preserves where each fact came from | Analysts must be able to audit a claim | Source name, payload hash, safe field names, timestamps, and derivations are exposed in lineage |
| Enrichment | Adds approximate country, city, ASN, and coordinates to literal IPs | Infrastructure context helps triage and visualization | Backend-only lookup with positive and negative caching and request pacing |
| Confidence | Gives an explainable priority score | Analysts need ordering, not another flat list | Versioned points are assigned for source quality, corroboration, recency, and context |
| ATT&CK mapping | Associates known malware families with techniques | ATT&CK gives analysts a common behavior vocabulary | Official technique data plus a reviewed family-to-technique catalog |
| Campaign clustering | Suggests groups of related infrastructure | Relationships are easier to inspect as groups | NetworkX graph construction followed by deterministic Louvain communities |
| Detection rules | Drafts Sigma and Suricata content | Intelligence is more useful when it can support detection | Stable templates, escaped values, provenance, and mandatory review labels |
| Investigation workbench | Checks up to 100 observables at once | Real analyst work often starts with a pasted alert list | Refangs and normalizes input, performs exact local lookup, separates matched/unmatched/invalid values |
| STIX export | Creates an interoperable indicator bundle | Findings should move to other tools | Valid matches only are serialized as STIX 2.1 with stable identifiers |
| Map | Displays geographic and infrastructure patterns | Spatial concentration can reveal context | ArcGIS WebGL renders clusters/heatmaps; a raster fallback remains usable without WebGL |
| On-demand report | Creates a weekly CTI draft when requested | A serverless portfolio deployment should not pretend it has a persistent cron worker | The backend selects the last complete week, builds deterministic facts, then asks the selected provider for prose |
| Ask ThreatMesh | Answers natural-language questions about stored data | It gives a faster entry point for non-SQL users | The server retrieves bounded facts first and validates returned evidence IDs |

## 6. End-to-end flow

### Step 1: collect

Each connector downloads one known feed with timeouts, response-size limits, retry
rules, and source-specific authentication. ThreatMesh never opens, scans, or probes
an indicator.

### Step 2: normalize and store

The parser converts each source row into `NormalizedIOC`. The service canonicalizes
the value and builds a type-and-port-aware identity. Upserts are idempotent, so
running the same feed again updates the observation instead of creating uncontrolled
duplicates. Every run records received, inserted, updated, rejected, and failure
counts.

### Step 3: enrich

Only literal public IP addresses are sent for geolocation. Domains are not resolved
automatically because DNS resolution would add active network behavior and unstable
meaning. Results are cached. Failed or unsupported lookups are also cached for a
shorter period so one bad address cannot starve the queue.

### Step 4: analyze deterministically

The analysis pipeline selects one evidence scope. If live observations exist, it
uses live evidence. Otherwise it can use the marked demo corpus. It never combines
demo and live records for corroboration or campaign edges.

It then:

1. calculates confidence snapshots;
2. maps reviewed malware families to ATT&CK techniques;
3. rebuilds candidate campaigns;
4. generates eligible detection-rule drafts.

### Step 5: serve typed API data

FastAPI routes return Pydantic-validated response shapes. PostgreSQL/PostGIS owns
durable data and spatial values. SQLite is supported for fast tests and simple API
development, but production geography should use PostGIS.

### Step 6: investigate and communicate

React Query loads API data into the analyst console. An analyst can pivot from a
map or table into exact evidence lineage, paste a list into the workbench, download
validated exports, inspect possible campaigns, or request grounded prose.

## 7. The confidence score

The current score is a bounded heuristic with a maximum of 100 points:

- up to **40 points** for source quality;
- up to **20 points** for independent corroboration;
- up to **30 points** for recency; and
- up to **10 points** for useful context such as a malware family.

The exact breakdown, formula version, and scoring time are stored with the IOC.
This makes the score explainable and testable.

What the score means: it helps order an analyst queue.

What it does not mean: it is not the probability that an IOC is malicious, a risk
score for a company asset, or permission to block traffic.

## 8. Campaign clustering

Campaign analysis is often overclaimed. ThreatMesh uses careful language:

- a node is an IOC observation identity;
- an edge requires meaningful shared context;
- time proximity alone does not create an edge;
- communities are found with Louvain clustering;
- a campaign needs at least two different indicators; and
- output is a correlation candidate, not actor attribution.

This design is useful because it surfaces patterns without pretending that an
algorithm knows attacker intent.

## 9. Evidence lineage

The evidence view is one of the strongest parts of the project. For an indicator it
can explain:

- its normalized identity and port;
- which source observations support it;
- when each source first and last saw it;
- which raw fields were present and the stored payload hash;
- how every confidence component was awarded;
- what geolocation evidence was used;
- whether ATT&CK mapping was curated or inferred;
- which campaign contains it;
- which rules were derived from it; and
- which reports explicitly mention it.

Raw secrets or unrestricted raw payloads are not returned to the browser. A hash
allows change/audit checks without exposing everything received from a feed.

## 10. How the AI features stay controlled

### Ask ThreatMesh

The assistant is not given database access and does not generate arbitrary SQL.
The backend recognizes supported filters, retrieves a bounded set of facts, creates
an allow-list of evidence IDs, and sends those facts to the model. When the answer
returns, the server removes unknown or forged citation IDs. The UI links accepted
citations to exact records.

Citation validation proves that a cited record was in that request's retrieved
evidence. It does not mathematically prove that every sentence follows from the
record, so the interface still presents the answer as assistance.

### On-demand report

The report action uses the previous complete weekly window. Deterministic SQL
aggregates and bounded samples are created first. The provider writes a narrative
from those facts. Reports are idempotent for a reporting window and evidence scope,
and remain marked for analyst review.

### Providers

- **Gemini** is convenient for public OSINT and a hosted demonstration.
- **Ollama** keeps prompts on a local machine and is better for private data.
- **Disabled/static operation** lets the core platform run without an LLM.

Provider keys stay on the backend. They must never be placed in a `VITE_` variable,
because Vite variables are built into browser JavaScript.

## 11. Map and geolocation design

The map is intentionally a flat world map with a minimum zoom that keeps the
viewport filled; this avoids exposing black space around a small map when users zoom
out. The primary view uses ArcGIS WebGL for clustering, heatmaps, and location
context. A raster ArcGIS fallback supports browsers or machines where WebGL cannot
start.

Geolocation is only an estimate of network infrastructure. It is not the location
of a person and may not be the exact location of a server. The context circles are
illustrative, not a measured error radius. This is stated in the product rather
than hidden.

## 12. Security and reliability controls

- passive collection only; no scanning or exploitation;
- server-side secrets and `.env` files ignored by Git;
- admin-key protection for pipeline-changing operations;
- separate public and AI request-rate limits;
- bounded feed and ATT&CK downloads;
- request timeouts and limited retries;
- no forwarding the abuse.ch key across redirects;
- structured errors and request IDs;
- CORS and trusted-host configuration;
- content/security headers in middleware and Nginx;
- asynchronous job locks to prevent duplicate local runs;
- PostgreSQL advisory lock for a single external coordinator;
- configurable retention cleanup;
- database migrations instead of implicit production schema creation;
- deterministic demo data clearly separated from live evidence; and
- network-free tests for important behavior.

## 13. Why this is a good cyber-security project

This is stronger than a dashboard that only displays API data.

1. **It models a real analyst workflow.** Collection, triage, investigation,
   detection, reporting, and export are connected.
2. **It makes trust visible.** Confidence, provenance, scope, and limitations are
   first-class data.
3. **It uses AI in a defensible role.** The model communicates facts but does not
   make core security decisions.
4. **It is standards-aware.** ATT&CK, Sigma, Suricata, STIX, GeoJSON, and PostGIS
   make the work transferable.
5. **It handles engineering details.** Migrations, idempotency, caching, rate
   limiting, retries, health checks, concurrency control, and CI are present.
6. **It is honest.** Unknown does not mean safe, a graph cluster is not attribution,
   and approximate coordinates are not exact truth.
7. **It is demo-friendly.** Deterministic seed data makes the complete workflow
   available without leaking credentials or depending on live services.

## 14. How ThreatMesh helps

An analyst can paste observables from an alert, see which ones occur in retained
public evidence, understand why a result is important, pivot to related campaigns
and behavior, then export only verified matches. A manager can request a readable
weekly summary. A detection engineer can review a proposed rule together with its
source. A student can study how feed, GIS, graph, API, AI, and frontend layers fit
together in one defensible system.

## 15. Honest limitations

- Public feeds are incomplete and may contain stale or incorrect records.
- A missing match means “not found in this retained corpus,” not “safe.”
- IP geolocation is approximate and the free `ip-api` endpoint has licensing and
  transport limits; it is not suitable for commercial production as configured.
- Malware-to-ATT&CK mapping is intentionally small and curated.
- Graph communities show shared context, not ownership or attribution.
- Detection rules are templates and require tuning against local telemetry.
- AI citations are identity-validated, but semantic support still needs review.
- Vercel is suitable for a portfolio UI and request-driven API, but not for a
  persistent background scheduler. On-demand reporting is therefore the main
  hosted workflow.
- The current app has an administrator key for privileged operations, not a full
  multi-user identity and role system.
- The platform has no organization-specific asset inventory, so it measures
  intelligence confidence rather than business risk.

Stating these limits is a strength in an interview. Mature security engineering is
about knowing what a system can and cannot prove.

## 16. Improvements made during the final review

- Added a complete, plain-English architecture and interview guide.
- Added a file-by-file codebase guide for maintainers and reviewers.
- Corrected corrupted punctuation on the report page that could display as
  broken encoding characters.
- Kept on-demand reports as the deliberate public-deployment experience. The
  backend scheduling code remains available for persistent self-hosted operation,
  but the Vercel interface does not promise a cron worker it cannot own.

No extra headline feature was added just to increase the feature count. The project
already covers many areas; clearer documentation and a coherent trust model add
more value than another weak integration.

## 17. Recommended future work

### Highest value

1. **Real identity and RBAC.** Add login, analyst/admin roles, session management,
   and an audit log before allowing multiple users.
2. **Saved investigations.** Store a case name, pasted inputs, exact evidence
   snapshot, analyst notes, disposition, owner, and export history.
3. **Allowlists with expiry.** Record why a common or approved indicator is
   suppressed, who approved it, and when the exception expires.
4. **Production geolocation.** Replace the free HTTP lookup with a licensed HTTPS
   service or an offline GeoLite database.
5. **Observability.** Add Prometheus/OpenTelemetry metrics, error tracing, job
   duration, feed freshness alerts, and dashboards.

### Valuable after the data model grows

6. Add CVE observations, CISA KEV, EPSS, and an asset inventory together. Without
   asset exposure, vulnerability scores would look impressive but make weak
   decisions.
7. Add TAXII 2.1 collections when a durable host, authentication, pagination,
   manifests, and collection authorization exist.
8. Add analyst feedback to measure false positives and recalibrate confidence
   weights using real outcomes.
9. Add integration tests against a real PostGIS instance and browser end-to-end
   tests for the main investigation flow.
10. Add signed release artifacts and an SBOM for supply-chain maturity.

## 18. Interview demonstration plan

A strong demonstration takes about five minutes:

1. Start on **Overview**. Explain live/demo/mixed provenance and the map's
   uncertainty warning.
2. Open an indicator. Show its confidence breakdown and evidence lineage.
3. Open **Investigate**. Paste several valid, invalid, defanged, and unknown values.
   Explain why unknown is not called safe.
4. Download a STIX bundle and mention deterministic IDs.
5. Open a campaign. Explain graph edges and why the result is only a candidate.
6. Open a detection rule. Point to provenance and “review required.”
7. Ask a supported question in **Ask ThreatMesh** and open one returned citation.
8. Finish with the architecture rule: deterministic facts first, AI prose second.

Do not spend most of the demo changing filters. Show evidence and design decisions;
those are what make the project memorable.

## 19. Common interview questions and model answers

### What did you personally build?

> I designed the project as a complete CTI workflow: source-specific ingestion,
> normalization, an evidence data model, deterministic analysis, typed APIs, and an
> analyst UI. I also added defensive engineering such as bounded downloads,
> idempotent writes, source separation, citation validation, tests, and deployment
> configuration. The important part was not connecting APIs; it was preserving
> meaning and trust as data moved between layers.

### Why FastAPI?

> The workload has asynchronous HTTP collection and a typed JSON API. FastAPI works
> well with async code, Pydantic validates boundaries, and automatic OpenAPI docs
> make the service easy to inspect. Python also has strong data, graph, and security
> libraries.

### Why PostgreSQL and PostGIS?

> PostgreSQL provides durable relational constraints and good aggregation. PostGIS
> stores coordinates as real spatial values and provides spatial indexing and
> queries. SQLite is kept only as a fast development and test path.

### Why React and React Query?

> The console contains several stateful workspaces. React gives reusable UI
> components, while React Query handles cache keys, loading, error, and refetch
> behavior around the API. The client also makes demo fallback explicit instead of
> silently replacing a failed live request.

### Why ArcGIS?

> The project needs real GIS rendering: feature clustering, heatmaps, world imagery,
> and a clear raster fallback. PostGIS remains the data engine; ArcGIS is the browser
> visualization layer. A public basemap works without a key, while premium services
> can use a restricted browser key.

### How do you prevent duplicates?

> I normalize each observable, retain its declared type and port where relevant,
> and upsert by a stable source identity. Re-running a feed is idempotent. Analysis
> artifacts also use stable identities or period keys where possible.

### Why is the port part of identity?

> An IP serving malicious traffic on port 443 is not always the same observation as
> the same IP on port 8443. Dropping the port can merge distinct infrastructure and
> produce unsafe network rules. Tests cover this boundary.

### How does confidence work?

> It is a versioned 100-point heuristic based on source quality, corroboration,
> recency, and context. The full component breakdown is stored. It prioritizes
> review; it is not a probability or malicious verdict.

### Why not let the LLM calculate confidence?

> A security score must be repeatable, testable, and explainable. A language model
> can change its answer between calls and may invent reasoning. ThreatMesh calculates
> the facts deterministically and uses the model only to communicate them.

### Is the assistant really RAG?

> It is retrieval-first grounded generation over structured database facts. The
> server performs constrained retrieval, not arbitrary text-to-SQL, and validates
> citation identities after generation. I describe it precisely rather than claiming
> a vector database that the project does not use.

### Can the assistant hallucinate?

> Yes, any generative model can. ThreatMesh reduces the risk with bounded facts,
> strict prompts, structured output parsing, an evidence allow-list, and visible
> citations. Those controls do not prove every sentence, so analyst review remains
> required.

### How do campaign candidates work?

> Indicators become graph nodes and meaningful shared context creates weighted
> edges. Louvain community detection finds dense groups. Time alone cannot connect
> nodes, and small invalid groups are rejected. The result suggests investigation;
> it does not attribute an actor.

### How do you handle demo and live data?

> Every record has provenance. If live data exists, operational analysis uses the
> live partition. Demo and live observations never corroborate each other or create
> joint campaign edges. The UI displays the current corpus mode.

### What happens when a feed changes format?

> Each connector owns its parser and rejects malformed rows without treating them as
> valid. Feed-run telemetry records partial and failed runs. Parser tests cover schema
> drift, timestamps, tags, response size, and transaction rollback.

### Why is report generation on demand?

> The portfolio deployment can run on serverless infrastructure, which does not own
> a persistent in-process scheduler. An on-demand weekly window gives a truthful,
> demoable workflow. The reusable scheduler/coordinator code remains available for
> a persistent GCP or self-hosted deployment.

### Why generate only the previous complete week?

> A complete period is stable and comparable. Generating against a partly completed
> week would make the same report title change throughout the week and weaken
> idempotency.

### Why not automatically deploy generated rules?

> Feed evidence can be wrong or irrelevant to a local network, and a generic template
> may be noisy. Rules include provenance and a review flag, but a detection engineer
> must tune and approve them before production use.

### Is IP geolocation accurate?

> It is approximate infrastructure context. It does not identify a person or an
> exact machine. The UI and documentation say this clearly and avoid presenting the
> uncertainty circle as a measured accuracy guarantee.

### What is the biggest technical risk?

> Semantic correctness across boundaries. A tiny normalization, port, provenance,
> or time-window mistake can make polished output misleading. That is why the code
> separates layers, preserves lineage, and tests these cases.

### How would you scale it?

> I would keep the stateless API horizontally scalable, move pipeline work to one
> controlled coordinator or queue workers, retain PostgreSQL as the source of truth,
> add connection pooling and pagination, and measure slow queries before introducing
> more infrastructure. The external coordinator already uses a PostgreSQL advisory
> lock to avoid duplicate ownership.

### How would you make it enterprise-ready?

> Identity, RBAC, tenant boundaries, immutable audit events, a licensed enrichment
> source, secret management, metrics/tracing, backups, disaster recovery, and a
> reviewed data-sharing policy would come before more visual features.

### What would you improve first?

> Saved, auditable investigations after adding identity. That converts a strong
> single-analyst workbench into a team workflow without weakening the evidence-first
> design.

## 20. Terms you should know

- **IOC:** indicator of compromise, such as an IP, domain, URL, or hash.
- **CTI:** cyber threat intelligence; evidence and analysis about cyber threats.
- **OSINT:** information collected from public sources.
- **Provenance:** where a fact came from and how it was transformed.
- **Idempotent:** safe to repeat without creating a different duplicate result.
- **ATT&CK:** MITRE's vocabulary for adversary tactics and techniques.
- **Sigma:** a generic format for log-detection rules.
- **Suricata:** a network intrusion detection/prevention engine and rule language.
- **STIX:** a standardized JSON language for cyber-threat information.
- **GeoJSON:** a JSON format for geographic features.
- **PostGIS:** PostgreSQL extensions for spatial data and queries.
- **Louvain:** an algorithm that finds communities in a graph by optimizing
  modularity.
- **RAG:** retrieval-augmented generation; retrieve evidence before asking a model
  to write an answer.
- **RBAC:** role-based access control.
- **TLP:** Traffic Light Protocol, a marking scheme for sharing information.

## 21. Final presentation advice

Say what the project proves, then say what it does not prove. Prefer words such as
“candidate,” “estimate,” “retrieved evidence,” and “review required.” Avoid saying
that AI detects attacks, that a map shows attacker location, or that an unmatched
IOC is safe. That precision will make the project sound more professional, not less.

For exact file responsibilities, continue with [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md).
