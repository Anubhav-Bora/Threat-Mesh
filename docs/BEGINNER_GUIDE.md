# ThreatMesh Explained in Very Simple English

This is the best document to read first if cyber security, programming, or threat
intelligence is new to you.

It explains the project slowly, defines the important words, and uses examples.
After this guide, read the [project and interview guide](PROJECT_GUIDE.md), then
the [file-by-file code guide](CODEBASE_GUIDE.md).

## 1. What is ThreatMesh?

Imagine that several trusted neighborhood watch groups publish lists of suspicious
cars. One group writes number plates, another writes colors, and another writes
where the cars were seen. Their lists use different formats and may repeat the same
car.

ThreatMesh does something similar for cyber security.

It collects public lists of suspicious internet items, puts them into one common
format, removes confusing duplication, adds useful context, and lets a human analyst
study the results.

Those suspicious internet items can be:

- an IP address;
- a domain name;
- a URL;
- a file hash; or
- an IP address together with a network port.

ThreatMesh does not attack, scan, open, or visit those items. It only reads public
information and analyzes its own stored copy. This makes the project passive and
defensive.

## 2. What problem does it solve?

Public threat feeds can contain thousands of rows. A list that large is difficult
for a person to understand.

An analyst needs answers such as:

- Where did this information come from?
- Did more than one source report the same thing?
- Was it seen recently or a long time ago?
- Is it connected to a known type of malware?
- Are several items related?
- Can I create a draft detection rule from it?
- Can I export it to another security tool?

ThreatMesh turns a pile of rows into an investigation workspace that helps answer
those questions.

It helps a person make a decision. It does not make the final decision for them.

## 3. The most important rule

The main rule of the project is:

> The computer calculates security facts using normal, testable code. AI is allowed
> to explain those facts, but AI is not allowed to change them.

For example, Gemini can turn stored facts into a readable report. Gemini cannot
decide that an IP has a confidence score of 90. The normal Python scoring code does
that calculation.

This matters because normal code can be tested and repeated. A language model can
sometimes invent information or give different wording.

## 4. Important cyber-security words

### Threat

A threat is something that could cause harm to a computer, network, user, or
organization.

Examples include malware, stolen passwords, a malicious website, or a botnet.

### Cyber threat intelligence, or CTI

Cyber threat intelligence is useful information about cyber threats. Good
intelligence includes evidence and context, not only a long list of values.

ThreatMesh is a CTI platform because it collects evidence and helps a person
understand it.

### OSINT

OSINT means **open-source intelligence**. It is information collected from public
sources.

In this project, OSINT does not mean open-source software. It means publicly
available threat information.

### IOC

IOC means **indicator of compromise**.

It is a clue that may be related to harmful activity. Examples are a suspicious IP,
domain, URL, or file hash.

An IOC is a clue, not automatic proof. A shared server can be used by both good and
bad customers. An old malicious domain may later change owners. This is why
ThreatMesh shows source, time, and context.

### IP address

An IP address is a network address used to find a device or service on a network.

An IPv4 address looks like `192.0.2.10`. An IPv6 address is longer and uses numbers
and letters separated by colons.

An IP address does not always identify one physical machine or one person. Cloud
services, proxies, VPNs, and shared hosting can make that assumption wrong.

### Domain

A domain is a human-readable internet name, such as `example.com`.

Computers normally translate a domain into an IP address using DNS. ThreatMesh does
not automatically resolve every domain, because that would add live network
activity and could change the meaning of stored evidence.

### URL

A URL is a complete address for something on the web. It can include the protocol,
domain, port, path, and query string.

Example:

```text
https://example.com:8443/download?id=7
```

The domain is only `example.com`. The URL contains more information.

### File hash

A file hash is a fixed-length fingerprint calculated from file content. SHA-256 is
a common example.

If the file changes, its hash normally changes. A hash helps identify an exact file,
but it does not explain what the file does.

### Port

A port is like a numbered door on a computer. Different network services listen on
different ports.

ThreatMesh keeps an IP and its port together when the source provides both. The
same IP on port 443 may represent different activity from that IP on port 8443.

### Malware

Malware means software designed to do harm or perform unwanted actions. It includes
trojans, ransomware, spyware, worms, and other malicious programs.

### Botnet

A botnet is a group of infected computers controlled together. Each infected
computer is sometimes called a bot.

### Command and control, or C2

C2 is the communication channel attackers use to control malware or infected
systems. Feodo Tracker provides public information about known botnet C2 servers.

### Feed

A feed is a source that regularly publishes updated threat data.

ThreatMesh currently has connectors for:

- **URLhaus**, which reports malware-related URLs;
- **ThreatFox**, which reports several IOC types with malware context; and
- **Feodo Tracker**, which reports botnet C2 IP and port observations.

### Source

The source tells us who supplied an observation. Source is important because an
analyst must be able to check where a claim came from.

### Observation

An observation means that a source reported an IOC at a certain time. It does not
mean ThreatMesh personally visited the IOC and proved it was malicious.

## 5. What does “campaign” mean here?

This is one of the most important project words.

In normal cyber-security language, a campaign is a group of related malicious
activities that appear to be part of the same larger effort.

For example, imagine these clues:

- several harmful IP addresses are connected to the same malware family;
- they use related network infrastructure;
- they were active during a similar period; and
- the relationships are stronger inside the group than outside it.

They may belong to one larger operation. An analyst may call that a campaign.

### What ThreatMesh actually creates

ThreatMesh creates a **candidate campaign**.

Candidate means “a possible answer that still needs checking.” The program groups
related indicators using a graph algorithm. It does not know the attacker's real
identity, plan, country, or organization.

Therefore:

- a campaign in ThreatMesh is a calculated group of related IOCs;
- it is useful for investigation;
- it is not proof that one attacker owns every IOC;
- it is not a confirmed real-world operation; and
- it is not actor attribution.

### A school-friend example

Imagine a class where students are dots. Draw a line between two students when they
share a club, travel on the same bus, or often work together. Groups with many lines
inside them appear naturally.

That does not prove every student in a group is a close friend. It only shows useful
relationships worth examining.

ThreatMesh does the same with indicators:

- each IOC is a dot, called a **node**;
- a meaningful relationship is a line, called an **edge**;
- a strongly connected group is a **community**; and
- the stored community becomes a candidate campaign.

ThreatMesh uses the Louvain community-detection algorithm to find these groups.
Time being similar is not enough by itself to create a relationship.

## 6. Words used in the data pipeline

### Connector

A connector is a small part of the backend written for one external feed. It knows
how to download and understand that feed's format.

There is a separate connector for URLhaus, ThreatFox, and Feodo Tracker. Keeping
them separate means one feed can change without mixing its special rules into every
other feed.

### Fetch

Fetch simply means download or request data.

### Parse

Parse means read text or JSON and understand which pieces have meaning. A parser
may decide that one field is an IP, another is a date, and another is a malware
name.

### Validate

Validate means check that data follows the expected rules. An impossible timestamp
or malformed IP should be rejected instead of silently stored as good evidence.

### Schema

A schema describes the expected shape of data. It says which fields exist and what
type of value belongs in each field.

### Normalize

Normalize means convert different source formats into one common ThreatMesh format.

For example, three feeds may use `ioc`, `indicator`, or `value` for the same idea.
After normalization, ThreatMesh can treat all of them consistently.

### Canonicalize

Canonicalize means choose one stable written form for equivalent values.

For example, domain names are not case-sensitive. `EXAMPLE.COM` and `example.com`
should not be treated as two unrelated domains.

### Refang and defang

Analysts sometimes write dangerous-looking links in a safer form so people do not
click them accidentally. This is called defanging.

Examples:

```text
hxxps://example[.]com
```

Refanging changes that text back into its normal machine-readable form before an
exact local lookup. ThreatMesh supports common defanged forms in the Investigation
page. It still does not visit the address.

### Deduplicate

Deduplicate means remove or combine unwanted duplicates.

### Upsert

Upsert combines “update” and “insert.” If a matching database row already exists,
update it. If it does not exist, insert a new row.

### Idempotent

Idempotent means repeating the same operation does not create a new incorrect
result each time.

If ThreatMesh reads the same feed twice, it should update the existing observation
rather than create endless duplicate rows. A report for the same completed period
and evidence scope should also reuse its stable identity.

### Batch

A batch is a limited group of items processed together. Batches prevent one job
from trying to load everything into memory at once.

### Bounded

Bounded means there is a clear maximum. ThreatMesh limits input counts, response
sizes, samples, and timeouts so an external source or user cannot cause unlimited
work.

## 7. Evidence and trust words

### Provenance

Provenance means the history of where information came from.

For an IOC, provenance can include:

- source feed;
- first-seen and last-seen time;
- fields present in the source record;
- a fingerprint of the raw source payload; and
- later results created from that evidence.

Provenance answers: “Why is this in the system, and what supports it?”

### Evidence lineage

Lineage is the full path from original evidence to later results.

For example:

```text
ThreatFox observation
  -> normalized IOC
  -> confidence components
  -> ATT&CK mapping
  -> candidate campaign
  -> draft detection rule
  -> report mention
```

The indicator detail view shows this path so an analyst can inspect it.

### Raw payload

The raw payload is the original record received from a source. ThreatMesh stores
safe evidence about it. The browser receives field names and a payload hash rather
than every unrestricted raw value.

### Payload hash

A payload hash is a fingerprint of the original source record. It helps identify
whether the record changed without exposing all of it in the UI.

### Corroboration

Corroboration means independent support from more than one source.

If two feeds report the same normalized IOC identity, confidence can increase. A
demo row cannot corroborate a live row, and different ports are not silently merged.

### Recency

Recency means how recently something happened. A very recent observation is usually
more useful for current triage than a very old one.

### Context

Context is extra information that helps explain an IOC, such as malware family,
source, port, country, or related behavior.

### Confidence score

ThreatMesh gives each analyzed IOC a score from 0 to 100. It uses normal Python
rules:

- source quality: up to 40 points;
- independent corroboration: up to 20 points;
- recency: up to 30 points; and
- useful context: up to 10 points.

The score helps decide what to review first.

It is not:

- a percentage chance that the IOC is bad;
- proof of malicious activity;
- the business risk to a company; or
- automatic permission to block something.

### Confidence band

A band turns a numeric score into a simple label such as low, medium, or high. The
numeric score and its detailed components remain available.

### Analysis pending

Analysis pending means the source record has arrived, but ThreatMesh has not yet
calculated its own current score. It avoids pretending a source hint is a completed
ThreatMesh score.

## 8. Enrichment and map words

### Enrichment

Enrichment means adding useful context to existing evidence.

ThreatMesh can add approximate country, city, network number, network owner, and
coordinates to a literal IP address.

### Geolocation

Geolocation estimates where network infrastructure is located.

It does not tell us the exact location of a person or attacker. An IP may belong to
a cloud provider, VPN, content-delivery network, or company gateway.

### ASN

ASN means **autonomous system number**. It identifies a network that controls a
group of internet routes. The ASN organization may be an internet provider, cloud
company, university, or large business.

### Latitude and longitude

Latitude and longitude are numbers used to describe a location on Earth.

ThreatMesh stores network-location estimates as geographic coordinates.

### PostGIS

PostGIS adds geographic data types and queries to PostgreSQL. It lets the database
store a location as a real geographic point and use spatial indexes.

### GeoJSON

GeoJSON is a JSON format for geographic data. The backend can send IOC points to the
map in this standard shape.

### ArcGIS

ArcGIS is the mapping technology used by the frontend. It draws the world map,
points, clusters, heatmaps, and location context.

The public ArcGIS basemap can work without an API key. Premium ArcGIS services may
need a restricted browser key.

### WebGL

WebGL lets a browser use the graphics card to draw interactive graphics. The main
map uses it for richer rendering.

If WebGL cannot start, ThreatMesh has a simpler raster-tile map fallback.

### Raster tile

A raster tile is one small image square that forms part of a map. Many tiles placed
together create the visible world map.

### Cluster on the map

A map cluster is different from a candidate campaign.

A **map cluster** groups nearby dots only to prevent overlap when zoomed out. It is
a visual convenience.

A **candidate campaign** groups indicators using analytical relationships. It is an
investigation result.

Do not confuse the two.

### Heatmap

A heatmap uses color intensity to show where many points are concentrated. It shows
density, not danger level and not attacker location.

### Location context circle

The circle around a location reminds the user that IP geolocation is uncertain. It
is an illustration, not a scientifically measured error radius.

### Cache

A cache stores a result so it can be reused. ThreatMesh caches geolocation results
to respect rate limits and avoid repeatedly requesting the same IP.

A negative cache temporarily remembers that a lookup failed. This prevents one bad
IP from blocking all later work.

## 9. MITRE ATT&CK words

### MITRE ATT&CK

MITRE ATT&CK is a public knowledge base and vocabulary for behavior observed in
cyber attacks.

ThreatMesh uses it to describe behavior linked to known malware families. It does
not use ATT&CK to claim who the attacker is.

### Tactic

A tactic describes the attacker's broad goal, such as gaining initial access or
maintaining control.

Think of a tactic as **why** a behavior is performed.

### Technique

A technique describes a method used to achieve a goal.

Think of a technique as **how** the behavior is performed.

### Malware-family mapping

ThreatMesh contains a reviewed mapping from known malware-family names to selected
ATT&CK techniques. It is intentionally small and explainable.

This is safer than asking AI to guess a technique from a name.

### ATT&CK STIX bundle

MITRE publishes ATT&CK data in STIX format. ThreatMesh can download a version-pinned
official bundle, validate it, and update its local technique catalog.

## 10. Detection words

### Detection

Detection means finding activity that matches a suspicious pattern in network or
log data.

### Detection rule

A detection rule tells a security tool what pattern to look for.

ThreatMesh creates drafts. It does not install or activate them automatically.

### Sigma

Sigma is a general rule format for matching patterns in security logs. Different
security products can translate Sigma into their own query language.

### Suricata

Suricata is a network threat-detection engine. A Suricata rule can look for certain
network addresses, ports, domains, or traffic patterns.

### SID

A Suricata SID is the rule's numeric identifier. ThreatMesh calculates stable SIDs
for its generated drafts.

### False positive

A false positive happens when a rule creates an alert for normal or harmless
activity.

Every organization's network is different. A generated rule must be reviewed and
tuned using local data before use.

### Human review required

This label means a trained person must inspect and approve the result. ThreatMesh
uses this label on generated rules and reports because automatic output is not final
truth.

## 11. Investigation and export words

### Investigation

An investigation is the process of collecting and checking evidence to understand
an event.

The ThreatMesh Investigation page accepts up to 100 observables. It does exact
lookup against the retained local corpus. It does not contact each IOC on the
internet.

### Matched

Matched means ThreatMesh found the normalized value in its stored corpus.

This proves a stored source observation exists. It does not by itself prove the
item is currently dangerous.

### Unmatched

Unmatched means the value is valid but not present in the retained corpus.

Unmatched does not mean safe. The public feeds may not know about it, the record may
have expired, or the threat may be new.

### Invalid

Invalid means ThreatMesh could not understand the input as a supported IOC type.

### Blocklist

A blocklist is a list of values that a security product may prevent from
communicating.

ThreatMesh excludes local, private, reserved, and documentation-only addresses from
its plain blocklist export to reduce accidental network damage. A human must still
review the rest.

### Export

Export means download data in a format another person or tool can use.

ThreatMesh supports STIX JSON, CSV, and review-required plain text for matched
investigation results.

### CSV

CSV means comma-separated values. It is a simple table format commonly opened in a
spreadsheet.

### STIX 2.1

STIX is a standard JSON language for cyber-threat information. It gives fields and
objects common meanings so different tools can exchange them.

ThreatMesh exports only matched, normalized indicators. Stable STIX IDs help a
receiving tool recognize the same item in later exports.

### TLP:CLEAR

TLP is the Traffic Light Protocol for information-sharing rules. `TLP:CLEAR` means
the information can be shared without special restrictions, subject to normal
copyright and data-source terms.

ThreatMesh uses it for its current public OSINT exports. Future private sources must
keep their original sharing restrictions.

## 12. AI words

### AI

AI is a broad term for computer systems that perform tasks that appear intelligent.
In ThreatMesh, the AI feature is a language model used to write text from supplied
facts.

### LLM

LLM means **large language model**. Gemini and models run by Ollama are examples.

An LLM predicts useful text. It is not a database and does not automatically know
which ThreatMesh facts are true.

### Gemini

Gemini is Google's hosted AI model service. ThreatMesh can send public OSINT facts
to Gemini and receive report or answer wording.

The Gemini key stays on the backend. It must not be placed in a Vite browser
variable.

### Ollama

Ollama is software for running supported language models on a local computer. It is
the privacy-oriented option because prompts do not need to go to a cloud AI service.

### Prompt

A prompt is the instruction and data sent to a language model.

ThreatMesh prompts tell the model to use only the supplied evidence and return a
controlled structure.

### Hallucination

A hallucination is information generated by an AI model that sounds convincing but
is unsupported or wrong.

ThreatMesh reduces this risk, but cannot make it impossible.

### Retrieval-first

Retrieval-first means the backend finds relevant database facts before the model is
asked to answer.

The model does not freely browse the database or invent SQL.

### RAG

RAG means retrieval-augmented generation. It means generation is given retrieved
evidence as context.

ThreatMesh uses structured database retrieval. It does not claim to use a vector
database when it does not.

### Citation

A citation points to the evidence used in an answer.

The server creates a list of allowed evidence IDs for each question. If a model
returns an unknown ID, ThreatMesh rejects that citation. Accepted IDs link to exact
indicators, campaigns, techniques, reports, or aggregate evidence.

This proves that the ID was available to the model. A human must still decide
whether the sentence correctly explains it.

### Grounded

Grounded means the generated text is based on supplied evidence rather than an
unrestricted answer from the model's memory.

## 13. Report words

### Reporting period

The reporting period is the fixed time range covered by a report.

The on-demand report uses the previous complete week. A completed week is stable;
the same report does not keep changing while the current week is still happening.

### Deterministic facts

Deterministic means the same valid input and code rules produce the same result.

Report counts, top families, techniques, and evidence samples are calculated before
the LLM writes prose.

### Executive summary

An executive summary is a short explanation of the most important information for
a busy manager.

### On-demand

On-demand means the report is created when the user presses the button. This is the
main hosted workflow because a Vercel serverless function does not continuously run
inside the background.

### Scheduled report

A scheduled report runs automatically at a chosen time. The backend still contains
scheduling support for persistent self-hosted or GCP coordinator deployments, but
the public Vercel interface intentionally uses the honest on-demand workflow.

## 14. Application and programming words

### Frontend

The frontend is what runs in the user's web browser. It contains the pages, buttons,
tables, charts, and map. ThreatMesh uses React and TypeScript.

### Backend

The backend runs on a server. It protects secrets, talks to feeds and the database,
performs analysis, and answers API requests. ThreatMesh uses Python and FastAPI.

### API

API means application programming interface. It is a controlled way for one program
to request data or an action from another program.

The browser calls endpoints such as `/api/v1/iocs` instead of reading the database
directly.

### Endpoint or route

An endpoint is one API address and action. For example, one route lists reports and
another route creates an on-demand report.

### Request and response

A request asks the API for something. A response contains the result or a structured
error.

### JSON

JSON is a text format for structured data. APIs commonly use it for requests and
responses.

### FastAPI

FastAPI is the Python web framework used to build the backend API. It supports
asynchronous work, validation, typed responses, and automatic API documentation.

### React

React is the frontend library used to build pages from reusable components.

### TypeScript

TypeScript is JavaScript with type checking. Types catch many mistakes before the
browser runs the code.

### React Query

React Query manages frontend API data, loading states, errors, caching, and
refetching.

### Component

A component is a reusable piece of the UI, such as a badge, map, indicator detail
panel, or navigation shell.

### Hook

A React hook is a function that shares stateful frontend behavior. ThreatMesh hooks
wrap API queries so pages use consistent cache keys and loading behavior.

### Python service

A service class contains application work that is larger than one API route. For
example, `IngestionService` owns feed synchronization and `ReportService` owns
report facts and storage.

### Asynchronous, or async

Async code can wait for slow work, such as an HTTP response or database query,
without blocking all other work in the process.

### Database

A database stores structured information durably so it remains available after the
application restarts.

### PostgreSQL

PostgreSQL is the main relational database used by ThreatMesh.

### SQLite

SQLite is a small database stored in one file. ThreatMesh uses it for fast tests and
simple backend development. It does not replace PostGIS for the full production
geographic setup.

### Table, row, and column

A database table is like a spreadsheet. A row is one stored item. A column is one
type of information about each item.

### Index

A database index is like the index at the back of a book. It helps the database find
specific rows faster.

### Migration

A migration is a versioned instruction for changing the database structure safely.

When a new field is needed, developers add a new Alembic migration instead of
manually changing production tables.

### Alembic

Alembic is the migration tool used with SQLAlchemy.

### SQLAlchemy

SQLAlchemy lets Python code define and query database models.

### Pydantic

Pydantic checks configuration, request, and response data against typed rules.

## 15. Operations and safety words

### Environment variable

An environment variable is a configuration value given to the application outside
the code.

Database addresses, provider choices, and API keys are environment variables.

### `.env` file

A `.env` file is a convenient local file containing environment variables. Real
`.env` files are ignored by Git because they can contain secrets.

An `.env.example` file contains safe placeholders and explains which variables are
available.

### Secret and API key

A secret is private information used to authenticate a program. An API key is one
kind of secret.

Backend keys such as abuse.ch and Gemini keys must never be committed or sent to the
browser. A `VITE_` variable is public because Vite includes it in built browser code.

### Authentication

Authentication answers: “Who or what is making this request?”

ThreatMesh currently uses an administrator API key for privileged pipeline actions.
It does not yet provide complete user accounts and login sessions.

### Authorization

Authorization answers: “What is this user allowed to do?”

A future multi-user version should have roles such as analyst and administrator.

### RBAC

RBAC means role-based access control. Permissions are assigned through roles rather
than handled separately for every user.

### Rate limit

A rate limit controls how many requests are accepted during a period. It reduces
abuse, accidental loops, and unexpected AI cost.

### Timeout

A timeout stops waiting after a safe amount of time. Without one, a broken external
service could leave a job waiting forever.

### Retry

A retry makes another attempt after a temporary failure. Retries are limited so
they do not create an endless loop.

### Job lock

A job lock prevents the same heavy job from running twice at the same time inside
one process.

### PostgreSQL advisory lock

An advisory lock is a lock coordinated through PostgreSQL. The external coordinator
uses one so two deployed coordinators do not both own the pipeline.

### Scheduler

A scheduler starts work at planned times. APScheduler is used for persistent
embedded deployment. Cloud Scheduler can start a GCP coordinator job.

### Retention

Retention means how long data is kept. ThreatMesh can delete stale IOC evidence,
old reports, old feed-run records, and old cache entries after the configured number
of days.

### Health check

The `/health` endpoint answers whether the web application process is alive.

### Readiness check

The `/ready` endpoint checks whether the application is ready to serve useful work,
including required dependencies such as the database.

### CORS

CORS is a browser security rule controlling which website origins may call an API.
Production should list the actual frontend origin rather than allow every site.

### Trusted host

A trusted-host list controls which hostnames the backend accepts in requests. It
helps reject suspicious Host headers.

### Security header

Security headers tell the browser to apply protections such as content restrictions
and safer framing behavior.

### Structured logging

Structured logs store important fields, such as request ID and status, in a form
that log tools can search reliably.

### Request ID

A request ID is a unique label for one API request. It helps connect an error seen
by a user with the matching server log.

## 16. Demo, live, mixed, and empty data

### Demo

Demo data is fake, safe, and repeatable data created only to demonstrate the
project. ThreatMesh marks every demo row.

### Live

Live means the data came from configured real public threat feeds.

Live does not mean perfectly correct or happening at this second. It means the
evidence is not the synthetic demo corpus.

### Mixed

Mixed means the database contains both demo and live rows.

The UI may display that fact, but operational analysis uses the live partition.
Demo rows never increase live confidence or create campaign edges with live rows.

### Empty

Empty means no current IOC observations are available.

If a live API succeeds but contains no data, ThreatMesh shows an empty state. It
does not quietly replace the result with fake data.

## 17. Every main screen explained

### Overview

This is the starting dashboard.

It shows:

- high-level counts;
- whether the corpus is demo, live, mixed, or empty;
- feed-health information;
- trends and distributions;
- the map; and
- administrator operations when enabled.

Use it to understand the current state, not to make a final blocking decision.

### Investigate

Paste up to 100 observables here.

ThreatMesh normalizes them, looks for exact matches in the local retained corpus,
and separates them into matched, unmatched, and invalid groups. You can export
matched results as STIX, CSV, or review-required text.

This page is the clearest real analyst workflow in the project.

### Indicators

This page lists stored IOCs. Filters help narrow the list. Opening one item shows
its context and evidence lineage.

### Campaigns

This page shows algorithm-created groups of related indicators.

Remember: these are candidate campaigns. They are investigation suggestions, not
proof of one attacker or confirmed actor attribution.

### ATT&CK

This page shows techniques from the local MITRE ATT&CK catalog and which behaviors
are currently connected to in-scope evidence.

### Detection rules

This page shows Sigma and Suricata drafts created from eligible high-confidence
observations. It includes provenance and review warnings. Downloading a draft does
not deploy it.

### Reports

This page creates and displays an on-demand report for the previous complete week.

The backend calculates facts, and Gemini or Ollama can write the explanation. Every
AI-written report requires analyst review.

### Ask ThreatMesh

This is the natural-language assistant.

The backend first retrieves a limited set of facts. The model receives those facts,
writes an answer, and returns citation IDs. The server accepts only IDs that were in
the retrieved evidence set.

### Settings

This page explains the current mode, privacy choices, providers, accounts, and
configuration boundaries. It does not show secret key values.

## 18. One IOC's complete journey

The following example uses an imaginary value. It is not a real threat claim.

1. ThreatFox publishes an observation for an IP and port.
2. The ThreatFox connector downloads a bounded response.
3. The parser checks the timestamp, IOC type, value, tags, and context.
4. The common ingestion code normalizes the value.
5. A stable identity includes IOC type and port.
6. The service upserts the observation into PostgreSQL.
7. A `FeedRun` row records how many source rows were received, accepted, rejected,
   inserted, and updated.
8. The enrichment service checks whether the IP is public and literal.
9. It reuses a cached location or requests approximate country/city/ASN data.
10. The confidence service calculates and stores every point component.
11. The ATT&CK service checks whether the malware family has a reviewed mapping.
12. The clustering service checks meaningful relationships with other IOCs.
13. The rule service may create review-required detection drafts if the observation
    is eligible.
14. The API returns a limited typed representation to the frontend.
15. The Indicators page displays it.
16. The lineage endpoint explains the original evidence and every derived stage.
17. Investigation can find the exact normalized identity.
18. A report or assistant answer may refer to it using a validated evidence ID.

At no point does ThreatMesh visit or attack the IOC.

## 19. How the parts work together

```text
URLhaus / ThreatFox / Feodo
          |
          | public feed records
          v
Python connectors
          |
          | normalized observations
          v
PostgreSQL + PostGIS
          |
          | stored evidence
          v
Scoring + ATT&CK + graph clustering + rule drafts
          |
          | typed results
          v
FastAPI
          |
          | JSON / GeoJSON
          v
React pages + ArcGIS map
          |
          v
Human analyst decision
```

Gemini or Ollama sits beside this flow. It receives selected facts from the backend
and returns text. It is not the owner of the database or analysis pipeline.

## 20. Why each technology is used

| Technology | Very simple meaning | Why ThreatMesh uses it |
|---|---|---|
| Python | General programming language | Strong libraries for APIs, data, graphs, and tests |
| FastAPI | Python web/API framework | Async requests, validation, typed contracts, API docs |
| Pydantic | Data checker | Rejects invalid configuration and API input |
| SQLAlchemy | Python database layer | Defines models and builds safe queries |
| Alembic | Database change tracker | Applies versioned schema changes |
| PostgreSQL | Main database | Durable relational evidence and good aggregation |
| PostGIS | Geographic database extension | Stores and indexes real spatial points |
| APScheduler | Clock for backend jobs | Runs recurring work on persistent deployments |
| NetworkX | Graph library | Builds IOC relationship graphs |
| Louvain | Community algorithm | Finds strongly connected candidate groups |
| React | Browser UI library | Builds reusable interactive pages |
| TypeScript | Typed JavaScript | Catches frontend mistakes earlier |
| React Query | API-state helper | Manages loading, errors, caching, and refetching |
| ArcGIS Maps SDK | GIS browser tools | Draws clusters, heatmaps, and map context |
| Vite | Frontend build tool | Runs development and creates production assets |
| Vitest | Frontend test runner | Tests browser components and utilities |
| Pytest | Backend test runner | Tests services, API, migrations, and safety rules |
| Ruff | Python quality tool | Checks and formats Python code |
| ESLint | Frontend code checker | Finds JavaScript/TypeScript problems |
| Prettier | Frontend formatter | Keeps code style consistent |
| Docker | Application container tool | Makes local setup reproducible |
| Docker Compose | Multi-container starter | Runs database, backend, and frontend together |
| Vercel | Serverless web host | Convenient portfolio frontend/request API deployment |
| GCP | Cloud platform | Better option for a persistent coordinator and scheduled jobs |

## 21. What the project can prove

ThreatMesh can prove things such as:

- a stored source reported a particular normalized IOC;
- the observation had certain safe source fields and a payload fingerprint;
- more than one stored source corroborated the same identity;
- the score used a specific formula version and point breakdown;
- a curated malware mapping connected the evidence to selected ATT&CK techniques;
- an algorithm placed the IOC in a candidate community;
- a rule or report was derived from a known evidence snapshot; and
- an assistant citation ID belonged to that request's retrieved evidence.

## 22. What the project cannot prove

ThreatMesh cannot prove that:

- every feed record is correct;
- an IOC is still harmful now;
- an unmatched IOC is safe;
- an IP location identifies a person;
- a candidate campaign belongs to one confirmed attacker;
- an ATT&CK mapping proves the exact behavior occurred in your network;
- a generated rule will have no false positives;
- every AI sentence is perfectly supported; or
- a confidence score is the probability of maliciousness.

These limits are normal. A professional system states them clearly.

## 23. Testing words

### Unit test

A unit test checks a small function or component in isolation.

Example: verify that CSV quotes are escaped correctly.

### Integration test

An integration test checks several pieces working together.

Example: call an API route, write to the test database, and verify the response.

### Mock or fake

A mock/fake replaces an external dependency during a test. ThreatMesh tests do not
need to call live threat feeds or Gemini.

### Regression test

A regression test protects against a bug returning later.

The frontend includes a test for pressing Enter in Ask ThreatMesh without causing
the previous black-screen failure.

### CI

CI means continuous integration. GitHub Actions automatically checks formatting,
lint, types, tests, and builds when code changes.

### Lint

Linting finds suspicious code, unused values, inconsistent imports, and style
problems before they become harder to review.

### Type check

A type check verifies that code uses values in the expected way. For example, it
can catch code that treats a number as if it were a string.

## 24. Deployment words

### Local development

Local means the project runs on your own computer. Docker Compose is the easiest
way to start the full stack locally.

### Build

A build turns source code into production-ready files or a container image.

### Container

A container packages an application with its runtime and dependencies in a
repeatable environment.

### Image

A container image is the stored package used to create running containers.

### Serverless

Serverless means the cloud platform starts application instances when requests
arrive. It does not mean there are no servers; it means the platform manages them.

Vercel's serverless backend is good for request-driven demonstrations, but it should
not pretend one process stays alive forever to run APScheduler.

### Cloud Run

Cloud Run runs containers on Google Cloud. A Cloud Run service can host the API,
while a Cloud Run Job can run the external coordinator when Cloud Scheduler calls
it.

### Secret Manager

Secret Manager stores sensitive values such as API keys outside code and deployment
files.

### Environment

An environment is a place where the app runs, such as local development, test,
staging, or production. Each environment should have its own configuration and
secrets.

## 25. How to explain the project in an interview

Start with the problem, not the technology list:

> Public threat feeds provide useful clues, but they are noisy, repeated, and hard
> to trust without context. I built ThreatMesh to turn those feed observations into
> an evidence-backed analyst workflow. It preserves provenance, calculates an
> explainable priority score, maps reviewed behavior to ATT&CK, suggests candidate
> campaigns through graph analysis, and creates review-required outputs. AI is used
> only after deterministic facts are retrieved.

Then show one example:

> If an analyst pastes an IP and port into Investigate, ThreatMesh normalizes the
> identity, checks the retained corpus, shows the sources, score components,
> location limitations, ATT&CK context, campaign membership, and derived rules. An
> unmatched value is called unknown, not safe.

## 26. Short answers to beginner interview questions

### Is ThreatMesh an antivirus?

No. It is a threat-intelligence and investigation workspace. It does not scan files
on a computer or automatically remove malware.

### Does it block bad IP addresses?

No. It can create a review-required blocklist or detection-rule draft. A human and
the organization's normal change process decide whether to deploy it.

### Does the map show where the hacker lives?

No. It shows an approximate location associated with network infrastructure. That
may be a cloud server, VPN, proxy, or provider location.

### Does a campaign mean one hacker?

No. In ThreatMesh it means a possible group of related IOCs found by an algorithm.
It is a lead for investigation, not confirmed attribution.

### Does high confidence mean definitely malicious?

No. It means the stored evidence has stronger source, corroboration, recency, and
context signals. It is a triage score.

### Does “not found” mean safe?

No. It means the value was not found in this stored corpus.

### Is the AI making security decisions?

No. It writes explanations using facts prepared by normal code. Humans make the
final decision.

### Why keep raw evidence history?

Because an analyst should be able to ask where a claim came from and how a later
result was created.

### Why use a graph?

Threat relationships are not naturally a simple list. A graph can represent many
items and their connections, which helps find groups worth investigating.

### Why use demo data?

Demo data makes the project safe and repeatable without requiring accounts or
depending on live services. It is always marked and never strengthens live results.

### What is the strongest project feature?

The evidence-first design. ThreatMesh connects ingestion, provenance, explainable
analysis, investigation, exports, and controlled AI instead of only drawing a nice
dashboard.

### What should be built next?

Real user login and role-based access, followed by saved investigations with owner,
notes, evidence snapshot, disposition, and audit history.

## 27. A simple story you can remember

Remember ThreatMesh using seven verbs:

1. **Collect** public observations.
2. **Clean** them into one common format.
3. **Remember** where every fact came from.
4. **Explain** priority and relationships with normal code.
5. **Investigate** exact evidence without contacting suspicious systems.
6. **Export** useful drafts that require human review.
7. **Communicate** selected facts with controlled AI.

If you can explain those seven steps and the limits of each one, you understand the
heart of the project.

## 28. What to read next

- [PROJECT_GUIDE.md](PROJECT_GUIDE.md) gives the professional problem statement,
  architecture, research, limitations, roadmap, demo plan, and detailed interview
  answers.
- [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md) explains the runtime flows and every major
  file in the repository.
- [methodology.md](methodology.md) records exact analytical rules.
- [architecture.md](architecture.md) records component and trust boundaries.
- [operations.md](operations.md) explains how an operator runs and maintains the
  system.
