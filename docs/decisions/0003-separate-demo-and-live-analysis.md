# ADR 0003: Keep demo and live evidence analytically separate

- Status: Accepted
- Date: 2026-08-26

## Context

ThreatMesh ships deterministic seed data so an evaluator can explore the
product without accounts or network calls. A successful API response does not
prove that its records came from live feeds: a database may contain demo rows,
live observations, or both. Merely showing a global “mixed” badge would still
allow synthetic records to corroborate a live IOC, form a campaign edge, alter
an aggregate, or enter generated detection and narrative content.

## Decision

Dataset provenance is persisted on observations and derived artifacts, exposed
through the API, and rendered in the interface. Confidence corroboration and
campaign graph edges never cross the demo/live boundary. When a reporting,
assistant, rule-generation, feed-health, or aggregate workflow encounters both
provenances, its operational scope is live data; demo data remains separately
inspectable and visibly labeled. A demo-only corpus remains fully functional so
the account-free quick start still demonstrates the pipeline.

## Consequences

- Seeded content cannot silently influence an operational conclusion.
- Mixed databases remain understandable, although a clean database is still
  recommended before evaluating live collection.
- Every new analytic or generated artifact must preserve and test provenance.
- API consumers can distinguish corpus composition from the active analytical
  scope rather than inferring either from transport success.
