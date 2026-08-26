# ADR 0002: Visualize IP geolocation as an estimate

- Status: Accepted
- Date: 2026-08-26

## Context

IP geolocation frequently resolves to a provider, exchange point, or city
centroid rather than a host's physical location. A precise pin visually
overstates that accuracy and can encourage incorrect attribution.

## Decision

ThreatMesh renders geolocated activity with translucent uncertainty halos and
density views. Copy in the interface describes the location as an estimate.
Country and ASN aggregation are used for analysis; coordinates are never
presented as evidence about a person or exact facility.

## Consequences

The map communicates patterns without implying precision the source cannot
provide. Operators must use independent evidence for attribution or response
decisions.
