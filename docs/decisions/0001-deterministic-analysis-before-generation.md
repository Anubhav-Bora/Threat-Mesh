# ADR 0001: Deterministic analysis before text generation

- Status: Accepted
- Date: 2026-08-26

## Context

ThreatMesh needs readable intelligence reporting and natural-language answers,
but a language model is not a reliable source of security facts. Allowing a
model to invent queries or independently classify infrastructure would make
the system difficult to audit and could turn fluent output into false
confidence.

## Decision

All security-relevant facts are computed or retrieved before generation.
Scheduled reports receive aggregate statistics produced by the application.
The assistant uses a constrained, retrieval-first query plan and receives only
the matching records. Provider prompts explicitly require answers to remain
inside that supplied evidence.

`LLM_PROVIDER=disabled` is a supported operating mode. Gemini is optional for
public OSINT workflows, while Ollama provides a local alternative when data
must remain on the operator's machine.

## Consequences

The application remains useful without an AI provider, answers can cite their
evidence counts, and model output can be regenerated without changing the
underlying assessment. The assistant supports fewer open-ended questions than
an unconstrained text-to-SQL agent, which is an intentional safety trade-off.
