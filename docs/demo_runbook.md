# Offline conference demo runbook

Run from a prepared environment with project dependencies installed:

```bash
osiris --json demo conference --output ./demo-output
```

The command uses an embedded offline fixture and does not contact SpiderFoot or
any external service. Each invocation creates a new isolated `run.*` directory
containing a valid review-only capsule, a deliberately tampered capsule whose
verification fails, and a separate run whose dissemination export is blocked.
Capsule verification uses a public key held outside the capsule source.

Do not describe this as a legal-admissibility demonstration. The script is an
engineering continuity demo only; see `docs/audits/final_readiness_report.md`.
