# OSIRIS readiness report — interim

Date: 2026-07-16  
Branch: `worktree-1`  
Status: **NO-GO for final dissemination and unsupervised production use**

This is an interim engineering report, not a completion claim. It records the
current local verification evidence and remaining acceptance gaps.

## Implemented in this hardening increment

- Versioned authorization model with approved-status, expiry, scope, exclusion
  and active-collection checks; live SpiderFoot invocation is denied by default.
- Immutable local raw-evidence store with SHA-256/length verification.
- Case/run propagation through primary JSON artifacts and PROV-O JSON-LD
  provenance for the replay pipeline.
- Offline graph renderer without CDN dependencies and dashboard CSP/escaping
  improvements.
- Exact deterministic score reconstruction and evidence-preserving synthetic
  fairness counterfactual checks.
- Central MISP/PDF release policy: blocked reports are review-only and MISP
  dissemination raises an error.
- Local Ed25519-signed Evidence Capsule builder/verifier and CLI.
- Hash-linked append-only chain-of-custody records.
- Release-gated STIX 2.1 export, review-only legal-support draft, and an
  offline fixture-based conference-demo script/runbook.
- Python 3.12 project metadata, pinned cryptography dependency and compile/CLI
  CI checks.

## Executed verification

```text
.venv/bin/python -m pytest -q
130 passed in 18.57s

.venv/bin/python -m compileall -q -x '(^|/)(.venv|.git)(/|$)' .
exit 0

.venv/bin/python osiris.py --json --help
exit 0

git diff --check
exit 0
```

The tests include raw/capsule tamper rejection, unauthorized/expired scope
checks, release-policy export blocking, score reconstruction, malicious HTML
rendering, offline graph output, fairness evidence preservation and custody
chain modification detection.

## Unexecuted checks

Ruff, MyPy, Bandit, Semgrep, pip-audit, coverage, clean-room installation,
SBOM generation, browser automation and a live CI run were not executed in
this environment. No success claim is made for them.

## Remaining critical gaps

- No production object store/object lock, KMS/keyless Cosign, RFC 3161 trusted
  timestamps, in-toto attestations, SBOM, or complete capsule integration.
- No normalized assertion/corroboration model linking every analytical claim to
  immutable raw evidence.
- No strict evidence-constrained LLM response schema or adversarial
  prompt-injection suite.
- No full named robustness families, STIX/OpenCTI exports, legal certificate,
  jurisdiction profiles, API/RBAC/OIDC or industrial deployment layer.
- Documentation reconciliation, offline conference runbook, blocked/valid demo
  capsules and legal-review templates remain incomplete.

## Go/no-go verdict

| Use case | Verdict | Basis |
| --- | --- | --- |
| Offline engineering demonstration of current controls | Conditional GO | Only with synthetic/local fixtures and explicit review-only labels. |
| c0c0n final-report demonstration | NO-GO | Required end-to-end capsule/demo, legal, export and readiness deliverables are incomplete. |
| Controlled industrial pilot | NO-GO | Storage, access control, observability, interoperability and security scanning are incomplete. |
| Evidentiary/legal-review support | NO-GO | This software does not establish legal admissibility; legal templates and review process are incomplete. |
| Unsupervised production use | NO-GO | Authorization, AI, evidence, and deployment controls remain incomplete. |
