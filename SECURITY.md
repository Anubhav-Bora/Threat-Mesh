# Security policy

ThreatMesh processes untrusted public feed content. Treat every IOC, label,
URL, report fragment, and generated rule as hostile input even when it comes
from a reputable source.

## Reporting a vulnerability

Please use the repository's **Security → Report a vulnerability** workflow so
details can be discussed through a private GitHub Security Advisory. Include a
minimal reproduction, affected version or commit, likely impact, and any safe
mitigation you identified. Do not include live credentials, victim data, or a
weaponized payload.

If private vulnerability reporting is unavailable, open a public issue asking
for a private contact channel without disclosing exploit details.

## Supported versions

Until the first tagged release, security fixes are made on the latest `main`
branch only.

## Operational boundaries

- ThreatMesh performs passive collection from documented OSINT services. It
  does not scan, probe, exploit, or connect to listed infrastructure.
- API secrets belong in environment variables or a secrets manager. Browser
  keys must be restricted by origin and service scope.
- The built-in confidence score is prioritization metadata, not proof that an
  indicator is malicious.
- Model-generated prose and deterministic detection-rule templates require
  human review. They are never deployed automatically.
- Public IOC data can still contain dangerous links. The interface renders IOC
  values as text and does not make them directly navigable.
