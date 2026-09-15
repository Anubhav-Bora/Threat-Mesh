# ThreatMesh Product Research and Feature Decisions

## Executive decision

ThreatMesh should focus on the workflow between an alert and an analyst decision: accept a bounded set of observables, normalize them consistently, identify exact matches in retained evidence, expose confidence and provenance, and export only validated matches in interoperable formats. The highest-value near-term additions are therefore a bulk Investigation Workbench and STIX 2.1 bundle export.

The Vercel-facing report scheduler is removed from the interface. Serverless deployments intentionally disable cron, and presenting a paused schedule creates an unusable control. Weekly report generation remains available on demand. The backend scheduling capability remains for self-hosted deployments where a persistent worker exists.

## Evidence

STIX is an open language and serialization format for exchanging cyber threat intelligence. STIX 2.1 models indicators, sightings, malware, infrastructure, relationships, confidence, and other CTI concepts, making it a suitable export boundary for ThreatMesh evidence.[1] The normative specification explicitly describes a Bundle as a transport container for bulk STIX data outside TAXII, which fits a stateless serverless download workflow.[2]

TAXII 2.1 is an HTTPS protocol for persistent machine-to-machine CTI exchange through API roots and collections.[3] It is valuable for mature sharing programs, but a conformant server adds discovery, collection, manifest, filtering, authentication, pagination, and status requirements. A downloadable STIX bundle captures most immediate interoperability value without pretending that a free Vercel function is a durable TAXII service.

CISA's Automated Indicator Sharing guidance uses STIX for structured indicators and TAXII for transport, reinforcing the value of standards-based export.[4] FIRST's current Traffic Light Protocol is TLP 2.0; public OSINT that carries minimal foreseeable sharing risk can be labeled `TLP:CLEAR`.[5] ThreatMesh exports public-feed matches with that label while retaining a human-review warning.

Bulk lookup must avoid turning absence into a benign verdict. MISP warning lists exist because common indicators can produce false positives or irrelevant matches, while Sigma guidance requires explicit false-positive consideration in detection content.[6][7] The workbench therefore reports "not present in this corpus" rather than "safe," shows recency and corroboration, and excludes unmatched input from exports.

CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS are strong prioritization inputs for vulnerability management: KEV records confirmed exploitation, while EPSS estimates exploitation probability over the next 30 days.[8][9] They are not selected for this release because ThreatMesh does not currently ingest asset inventory or CVE observations. Adding scores without affected-asset context would create an attractive dashboard but weak operational decisions.

## Feature evaluation

| Candidate | Analyst value | Vercel fit | Data fit | Decision |
|---|---:|---:|---:|---|
| Bulk IOC investigation | High | High | High | Implement |
| STIX 2.1 bundle export | High | High | High | Implement |
| CSV/plain blocklist export | High | High | High | Implement |
| On-demand weekly report | Medium | High | High | Retain |
| Report scheduler UI | Low on Vercel | Low | Medium | Remove from Vercel UX |
| TAXII 2.1 server | High at enterprise scale | Low | Medium | Defer |
| CISA KEV + EPSS dashboard | High for VM teams | High | Low today | Defer until CVE/asset model exists |
| Multi-user case management | High for teams | Medium | Low today | Defer until identity and audit model exists |
| More generative AI | Uncertain | Medium | Medium | Defer; deterministic evidence remains primary |

## Implemented workflow

1. An analyst pastes up to 100 IP addresses, domains, URLs, or hashes.
2. The backend infers type and applies the same canonicalization used during ingestion.
3. Exact indicator identity is queried, preferring live evidence and then highest confidence and recency.
4. The response separates matched, valid-but-unobserved, and malformed values.
5. Each match includes source, corroboration count, malware context, confidence, and last-seen time.
6. Exports contain matches only: STIX 2.1 JSON, CSV, or a review-required plain blocklist.
7. Common defanged forms are normalized for matching while the original analyst input is preserved.
8. Private, reserved, local, and documentation values remain visible as evidence but are excluded from plain blocklists.

## Trust and safety constraints

- A match is evidence of a feed observation, not proof that blocking is appropriate.
- An unmatched value is unknown to the retained corpus, not safe.
- Input is bounded to 100 unique values and 2,048 characters per value.
- Lookup is read-only and performs no outbound reputation calls.
- STIX IDs are deterministic for stable downstream deduplication.
- Export uses `TLP:CLEAR` because current sources are public OSINT; future private sources must preserve their original handling restrictions instead.
- Confidence and ATT&CK mappings remain deterministic and are not changed by an LLM.

## Recommended roadmap

### Next

Add analyst-managed allowlists based on MISP warning-list concepts. This requires a durable model, reason, owner, expiry, and audit trail so exclusions cannot silently suppress evidence.

Add saved investigations only after authentication exists. A case should preserve input, matches, analyst disposition, timestamps, and exports; anonymous browser storage is not an adequate audit record.

### Later

Add KEV and EPSS only alongside CVE ingestion and an affected-asset inventory. Prioritization should combine active exploitation, probability, asset exposure, business criticality, and compensating controls.

Add a TAXII 2.1 collection service only when ThreatMesh has persistent hosting, collection-level authorization, pagination, manifest/version semantics, and operational monitoring.

## Sources

1. OASIS CTI. [Introduction to STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html).
2. OASIS. [STIX Version 2.1, Errata 01](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html), April 2025.
3. OASIS. [TAXII Version 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html), June 2021.
4. CISA. [How to Share Cyber Threat Information through AIS](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais/how-share-cyber-threat-information-through-ais).
5. FIRST. [Traffic Light Protocol 2.0](https://www.first.org/tlp/).
6. MISP Project. [MISP Training Materials](https://www.misp-project.org/misp-training/misp-training.pdf), warning lists section.
7. SigmaHQ. [Sigma Rules](https://sigmahq.io/docs/basics/rules.html), false-positive and metadata guidance.
8. CISA. [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
9. FIRST. [EPSS Frequently Asked Questions](https://www.first.org/epss/faq).
