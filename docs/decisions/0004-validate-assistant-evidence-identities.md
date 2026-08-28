# ADR 0004: Validate assistant evidence identities on the server

## Status

Accepted.

## Context

Retrieval-first generation limits the model to a bounded fact set, but a model
can still omit citations, copy an identifier incorrectly, or invent a plausible
record ID. Building citation chips from every retrieved row would make those
rows look cited even when the answer never referenced them.

## Decision

For every assistant request, ThreatMesh constructs an explicit evidence catalog
from typed query results. The model may cite only the catalog's opaque record
IDs. After generation, the API parses full citation tokens, preserves their
answer order, removes unknown IDs, and returns only allow-listed citation
objects plus an integrity state: `verified`, `partial`, or `absent`.

The browser renders plain React text and the typed citations returned by the
API. It never discovers citations by scanning the broader fact payload and
never injects generated HTML. Record citations open the exact IOC, campaign,
technique, or report workspace.

## Consequences

- A displayed citation is guaranteed to have been retrieved for that request.
- Prompt-like feed values cannot add themselves to the citation allow-list.
- Forged IDs remain observable through the integrity state without becoming
  clickable evidence.
- Identity validation does not prove that a citation supports every nearby
  natural-language claim; analyst review remains required.
- Numeric campaign IDs are snapshot references because campaign rebuilds do not
  yet preserve stable lineage. The response label remains the authoritative
  snapshot context for that answer.
