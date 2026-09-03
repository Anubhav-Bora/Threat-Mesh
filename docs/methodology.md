# Intelligence methodology and limitations

ThreatMesh is a prioritization and exploration tool for public threat data. It
does not establish attribution, prove malicious intent, or replace an
organization's incident-response process.

## Indicator handling

- Each row is a source observation and retains its source and original payload
  for auditability.
- Deduplication occurs within a source using normalized type, value, and port.
  The same canonical indicator observed by independent sources remains as
  separate corroborating observations; the interface labels record counts and
  distinct-indicator counts accordingly.
- URLs are displayed as inert text. ThreatMesh never visits an ingested URL or
  actively connects to an IP listed by a feed.
- Feed timestamps describe source observations, not necessarily the beginning
  or end of malicious activity.
- Demo provenance is persisted. Demo and live observations never corroborate or
  cluster together; when both exist, operational aggregates, retrieval, reports,
  and new detection candidates use live evidence.

## Confidence score

The score is a transparent operational heuristic combining four signals:

1. source reputation, contributing up to 40 points;
2. independent source corroboration, contributing up to 20 points;
3. time decay from the most recent observation, contributing up to 30 points;
   and
4. available context (malware family, ASN, and ATT&CK mapping), contributing up
   to 10 points.

The result helps an analyst order a queue. It is not a probability, verdict, or
authorization to block infrastructure. Threshold labels are deliberately
described as low, medium, and high *confidence*, not risk or severity.

Feed-supplied confidence is stored separately as source evidence. It is never
substituted for this formula. A completed calculation persists all four point
contributions, the formula version, and one UTC evaluation timestamp so the
displayed total can be audited later even as observation recency changes. A
newly collected record is labeled analysis-pending until that calculation runs.

The shared presentation bands are **high ≥ 70**, **medium 40–69.9**, and
**low < 40**. The default detection-candidate threshold is 70, so the dashboard,
scheduled report, API summary, and rule workflow reconcile to the same boundary.

## Campaign candidates

Graph clustering connects observations that share a canonical indicator, or
that share an ASN or malware family inside a bounded first-seen window. Time
alone never creates an edge. Louvain community detection groups dense
neighborhoods, and a persisted candidate must contain at least two distinct
indicator identities. Countries and source feeds are displayed as observed
context, not as relationship evidence. These groups are labeled **campaign
candidates** because shared hosting can still create coincidental
relationships. Analyst validation and external reporting are required before
attribution.

## ATT&CK mapping

Technique tags are inherited from a small, reviewable malware-family mapping
and resolved against the official MITRE ATT&CK STIX catalog. They describe
behavior publicly associated with a family; they do not prove that every IOC
performed every mapped technique.

## Geolocation

IP geolocation commonly represents an ISP, exchange, VPN exit, hosting region,
or city centroid. ThreatMesh uses translucent geodesic context circles and
aggregate views rather than exact-looking pins. The displayed radius is an
illustrative uncertainty buffer, not a provider-measured accuracy or confidence
bound. Coordinates must not be used to identify a person, physical device, or
facility. See
[ADR 0002](decisions/0002-geolocation-is-an-estimate.md).

## Generated content

AI-written reports summarize supplied aggregates. Assistant responses are
limited to retrieved database evidence. Each assistant request also receives a
server-built evidence catalog. Only provider citation IDs present in that exact
catalog are returned to the browser; forged IDs are removed and the response
reports whether citation identity validation was complete, partial, or absent.
This validates evidence identity, not the semantic correctness of every
sentence. Generated Sigma and Suricata rules are templates for human review,
testing, tuning, and change control. No generated content is automatically
deployed.
