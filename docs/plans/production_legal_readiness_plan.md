# Production and legal-readiness implementation plan

This plan is based on the 2026-07-16 baseline. It is intentionally phased so
that a release gate is delivered before presentation polish or integrations.

## Phase 0 — Establish a reproducible baseline

Goal: make clean, offline development and CI deterministic.

- Add canonical `pyproject.toml`, Python version policy, dependency groups and
  a reproducible dependency strategy.
- Add format, lint, type, security, compile, coverage and offline test jobs.
- Remove runtime network/cache dependence from generated artifacts.
- Record commands, results, migrations and limitations.

Exit criteria: documented clean install and deterministic test command; CI
fails for syntax/import/test/schema/manifest/offline-artifact defects.

## Phase 1 — Authorization, raw evidence and schemas

Goal: introduce an evidence-first case boundary.

- Add versioned case authorization, scope matching, expiration and collection
  mode enforcement. Active collection is denied by default.
- Add immutable local evidence store, raw-object metadata and checksum reads.
- Add normalized assertion schemas that require raw-evidence IDs, and emit
  JSON-LD provenance.

Exit criteria: unauthorized, expired and out-of-scope collection attempts fail
closed; normalization has traceable raw parents.

## Phase 2 — Deterministic analysis and audit redesign

Goal: replace prototype scoring/audits with release-grade decisions.

- Version the scorer, thresholds and configuration; make exact contribution
  reconstruction a hard invariant.
- Separate risk, confidence, sufficiency, data quality and audit status.
- Disable OCEAN and ideology in the default operational profile.
- Build matched-counterfactual fairness and named robustness test families.

Exit criteria: score/explanation reconstruction is exact and inadequate,
conflicting, stale or missing evidence cannot yield a benign released result.

## Phase 3 — Authoritative release gate and evidence capsule

Goal: allow only verified PASS runs to disseminate final outputs.

- Centralize a fail-closed release-policy decision and apply it to report,
  MISP, STIX and future OpenCTI paths.
- Generate review-only packages for failed/blocked runs.
- Build deterministic manifests, local-development signing, verification CLI,
  SBOM and step attestations.

Exit criteria: direct function calls, `force` flags, stale schemas and artifact
tampering cannot bypass the policy.

## Phase 4 — Safe offline presentation and integrations

Goal: demonstrate verified evidence without a network dependency.

- Replace CDN-backed graph/dashboard resources with local or static safe
  renderers; add malicious-input tests and CSP.
- Include all dashboard/report/export artifacts in the capsule manifest.
- Implement schema-validated STIX/MISP/OpenCTI release-only exports.
- Add legal-review templates, chain of custody, Docker Compose and API/service
  interfaces as independently tested optional foundations.

Exit criteria: a one-command offline demo shows valid, blocked and tampered
scenarios, with no remote resource requests.

## Phase 5 — Documentation and readiness review

Goal: make claims precisely match verified behavior.

- Reconcile README, architecture, whitepaper/c0c0n material and guides.
- Add threat model, operator/analyst/verification/legal-review/demo/migration
  guides.
- Perform the clean-room verification and publish final readiness report with
  actual test and security-scan output.

Exit criteria: no unsupported legal-admissibility, audit, AI or integration
claims remain; the final report has an explicit go/no-go verdict.
