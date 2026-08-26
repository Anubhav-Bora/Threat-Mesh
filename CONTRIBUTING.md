# Contributing to ThreatMesh

ThreatMesh welcomes focused fixes, new passive OSINT connectors, enrichment
improvements, detection content, and usability work. Keep every contribution
safe for defensive use and reproducible without paid services.

## Development workflow

1. Fork the repository and create a short-lived branch from `main`.
2. Copy `.env.example` to `.env`. Never commit credentials or raw private data.
3. Start the stack with `docker compose up --build`, or run each application
   locally using the instructions in the README.
4. Add or update tests for behavior you change.
5. Run `make lint` and `make test` before opening a pull request.

Use small, imperative commit messages. Conventional Commit prefixes such as
`feat:`, `fix:`, `docs:`, and `test:` are encouraged because they make the
history easy to scan.

## Connector requirements

New data-source connectors must:

- use only passive, legally accessible sources;
- document authentication, licensing, and rate limits;
- set finite network timeouts and bounded retries;
- preserve the source timestamp and raw source record;
- normalize records without silently increasing confidence; and
- include fixture-based tests that never depend on a live service.

## Detection content

Generated Sigma and Suricata content is an analyst starting point. Pull
requests must not describe generated rules as production-ready or wire them to
automatic blocking. Include a stable identifier, provenance, and a clear
human-review notice.

## Pull requests

Describe the problem, the design choice, verification performed, and any
operational or privacy impact. Screenshots are useful for visible interface
changes. A maintainer may ask for a smaller change when a proposal mixes
unrelated concerns.
