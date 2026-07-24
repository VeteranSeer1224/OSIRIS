# OSIRIS authorization and evidence hardening readiness report

Date: 2026-07-24
Branch: `worktree-1`
Status: **NO-GO for final dissemination and unsupervised production use**

This is an engineering verification record, not a production-readiness or
legal-admissibility claim. The scoped hardening increment is implemented, but
one required external dependency-audit lookup could not be executed locally.

## Implemented in this hardening increment

- Versioned, timezone-aware authorization with canonical domain/IP scope checks;
  validated active authorization now survives the complete SpiderFoot pipeline.
- Immutable content-addressed evidence blobs plus distinct per-run observation
  records; replaying bytes no longer reuses case or run metadata.
- Case/run propagation through primary JSON artifacts and PROV-O JSON-LD
  provenance for the replay pipeline.
- Offline graph renderer without CDN dependencies and dashboard CSP/escaping
  improvements.
- Exact score reconstruction, fail-closed audit parsing, explicitly
  `INCONCLUSIVE` scoring-only fairness, and separate robustness versus
  evidence-deletion sensitivity results.
- Typed release context revalidating signed authorization, validity, scope,
  mode, evidence hashes, complete identities, scoring, audit, provenance and
  signer identity. Caller-supplied PASS labels are not trusted.
- Evidence Capsules derive identity/release relationships from artifacts,
  reject inconsistent IDs, symlinks and secret/private-key material, and
  verify only against an external trusted Ed25519 public key.
- Hash-linked append-only chain-of-custody records.
- Release-gated exports and an idempotent installed-CLI conference demo that
  creates isolated review-only, tampered, and release-blocked scenarios.
- Installable Python 3.12 packaging plus compile, coverage, lint, type,
  security, dependency-audit, wheel, and demo CI gates.

## Executed verification

```text
python3.12 -m venv /tmp/osiris-quality-venv
/tmp/osiris-quality-venv/bin/python -m pip install -e '.[dev,report,graph]'
Successfully installed osiris-evidence-platform-0.1.0 and requested extras

/tmp/osiris-quality-venv/bin/python -m compileall -q . \
  -x '(^|/)(\.git|\.venv|build|osiris_evidence_platform\.egg-info)/'
exit 0

/tmp/osiris-quality-venv/bin/pytest -q
144 passed in 7.86s

/tmp/osiris-quality-venv/bin/coverage run -m pytest -q
/tmp/osiris-quality-venv/bin/coverage report -m
144 passed in 12.79s; TOTAL 4364 statements, 879 missed, 80% coverage

/tmp/osiris-quality-venv/bin/ruff check .
All checks passed

/tmp/osiris-quality-venv/bin/mypy
Success: no issues found in 23 source files

/tmp/osiris-quality-venv/bin/bandit -q -r . \
  -x ./.venv,./build,./osiris_evidence_platform.egg-info,./tests,./spiderfoot
exit 0

/tmp/osiris-quality-venv/bin/python -m pip wheel . --no-deps \
  --wheel-dir /tmp/osiris-final-wheels
Successfully built osiris-evidence-platform
wheel sha256: ce96c8f2c5efd16646c00660255e2031352b0dba98cb60738b1b04d6c676bd74

/tmp/osiris-quality-venv/bin/osiris --json demo conference --output <temp-root>
executed twice; both PASS, tamper_rejected=true, export_blocked=true,
two distinct run directories created

git diff --check
exit 0

.venv/bin/python -m pip_audit --local --vulnerability-service pypi \
  --format json --output reports/security/pip-audit.json
exit 1: 40 known vulnerabilities in 6 stale packages

/tmp/osiris-quality-venv/bin/python -m pip install --upgrade pip
/tmp/osiris-quality-venv/bin/pip-audit --local --vulnerability-service pypi \
  --format json --output reports/security/pip-audit-clean.json
No known vulnerabilities found
```

The test suite includes direct forged-map release bypass attempts, signed typed
release PASS, active authorization propagation, normalized target mismatch,
missing audit fields, repeated evidence observations, attacker re-signing,
capsule/internal identity consistency, private key and symlink rejection, and
tamper detection.

## Security-audit result

The local audit was executed after explicit authorization. The complete JSON
outputs are retained at `reports/security/pip-audit.json` and
`reports/security/pip-audit-clean.json`. The active legacy environment report
found 40 known vulnerabilities: cryptography 3.4.8 (14), Pillow 12.2.0 (20),
lxml 4.9.4 (2), pyOpenSSL 21.0.0 (1), setuptools 81.0.0 (2), and Torch 2.12.1
(1). The clean CI-equivalent environment, after the CI's pip upgrade, reports
no known vulnerabilities.

The dependency declarations now pin the audited fix generations: cryptography
49.0.0, Pillow 12.3.0, lxml 6.1.1, pyOpenSSL 26.3.0, setuptools 83.0.0, and
CPU Torch 2.13.0. The active-environment refresh was started but the 192 MB
Torch wheel download was cancelled before installation completed; it therefore
remains stale until the operator reruns the upgrade. Semgrep, SBOM generation,
browser automation, and a live GitHub Actions run were not part of this
increment and have no success claim.

## Remaining critical gaps

- The long-lived local `.venv` still has 40 findings until the updated pinned
  environment is installed and re-audited successfully; the clean CI-equivalent
  environment has no known findings.
- No production object store/object lock, KMS/keyless signing, RFC 3161 trusted
  timestamps, in-toto attestations, or SBOM.
- No normalized assertion/corroboration model linking every analytical claim to
  immutable raw evidence.
- No strict evidence-constrained LLM response schema or adversarial
  prompt-injection suite.
- No full extraction-path fairness rerun; current scoring-only fairness is
  correctly marked `INCONCLUSIVE`.
- No complete named robustness families, OpenCTI integration, legal certificate,
  jurisdiction profiles, API/RBAC/OIDC or industrial deployment layer.
- The bundled relationship view remains less interactive than presentation
  material may imply. Documentation reconciliation is still incomplete.

## Go/no-go verdict

| Use case | Verdict | Basis |
| --- | --- | --- |
| Offline engineering demonstration of current controls | Conditional GO | Installed CLI demo is repeatable with synthetic fixtures, external-key capsule verification, tamper rejection, and explicit review-only/release-blocked labels. |
| Conference hardening demonstration | Conditional GO | The scoped three-scenario demo passes; describe it only as an engineering control demonstration. |
| Controlled industrial pilot | NO-GO | External dependency audit, storage, access control, observability, interoperability and deployment controls remain incomplete. |
| Evidentiary/legal-review support | NO-GO | This software does not establish legal admissibility; legal templates and review process are incomplete. |
| Unsupervised production use | NO-GO | Authorization, AI, evidence, and deployment controls remain incomplete. |
