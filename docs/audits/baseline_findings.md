# OSIRIS baseline findings

Date: 2026-07-16  
Branch: `worktree-1`

## Baseline method

The tracked repository was inventoried and its Python sources, schemas, tests,
workflow, dependency manifest, sample artifacts, pipeline, graph renderer,
report exporter, XAI wrapper, and dashboard were reviewed. The initial test
command was run in the checked-in virtual environment because the system Python
does not have the project's test dependencies.

Initial result: **108 passed, 5 failed**. All five failures were graph tests:
`tldextract` attempted to create a cache under a read-only home directory. This
is an offline/reproducibility defect, not an assertion failure. The graph
extractor has been changed to use the package's bundled suffix-list snapshot
without a cache or network source; the suite must be rerun after this change.

## Confirmed findings

| Area | Status | Evidence |
| --- | --- | --- |
| Exact score reconstruction | Partially implemented | Deterministic stub scoring records contributions, and an existing test verifies rounded reconstruction. The score model and signed contribution contract are not versioned as a standalone evidence artifact. |
| Fairness isolation | Confirmed deficient | Existing fairness perturbation changes risk features as well as identity text (`tests/test_audit_fixes.py`). It is not a matched counterfactual test that preserves legitimate evidence. |
| Robustness release criteria | Confirmed deficient | Current checks use a pass boolean and local perturbations; they do not enforce the required named test families or a configured feature-stability policy. |
| Audit failures blocking dissemination | Confirmed deficient | `build_report()` deliberately creates a report after a failed audit and both `export_pdf()` and `export_misp()` lack a release-policy check. |
| STUB/FALLBACK release | Confirmed deficient | Pipeline defaults to a dry-run dossier and can export PDF/MISP artifacts. The report only displays a badge. |
| Offline graph | Confirmed deficient | The fallback renderer falls back to an unpkg CDN when a local vendor file is absent; PyVis output also needs offline verification. |
| Unsafe HTML/JavaScript embedding | Partially mitigated | Several values are escaped and embedded JSON replaces `<`, but generated graph/dashboard artifacts need a single strict safe-rendering policy and adversarial browser-level tests. |
| Digital signatures/trusted time | Missing | Lineage records SHA-256 hashes only. There is no signed manifest, signature verification, trusted timestamp, or attestation implementation. |
| Raw evidence preservation | Partially implemented | `RawScan.raw_module_output` and entity evidence IDs exist, but input is normalized into `raw_scan.json`; immutable byte-preserved raw objects and evidence-store semantics are absent. |
| Dashboard manifest inclusion | Missing | Dashboard is generated after lineage hashes are calculated, so it is not in the current lineage manifest. |
| Unsupported generic explanations | Confirmed deficient | The report includes generic attack-footprint language when no matching feature evidence exists. |
| Schema enforcement | Partially implemented | Pydantic models and validation functions exist, but pipeline normalization intentionally tolerates incomplete dossiers and artifact-level schemas are incomplete. |
| Documentation alignment | Confirmed deficient | README claims an audit-ready/court-style pipeline and describes default dry-run output, whereas release gating, signatures, raw evidence handling, and legal-review limitations are not implemented. |
| Explabox role | Partially aligned | README says Explabox provides cohort descriptives while custom signed weights provide per-dossier attribution; this must be reconciled across all docs. |
| OCEAN/ideology scoring | Confirmed deficient | Operational `Dossier` requires OCEAN psychology and permits ideology. The brief requires these dimensions disabled by default. |
| Missing evidence and risk | Requires redesign | Existing stub scoring includes insufficient-data flags but does not expose evidence sufficiency as an independent, release-gated decision. |
| Citation to immutable raw evidence | Missing | Entities contain aggregated evidence IDs, but assertions, report findings, and exports do not link to immutable raw object hashes. |
| Authorization/scanning scope | Missing | `DISCLAIMER.md` acknowledgement is the only pipeline gate. There is no versioned case authorization, target allow-list, expiry, or active-scan authorization enforcement. |
| CI/reproducibility controls | Confirmed deficient | CI only installs dependencies and runs pytest. There is no canonical `pyproject.toml`, lint/type/security checks, lockfile, coverage, compile check, or offline end-to-end gate. The CI pins Python 3.12 while README states Python 3.11. |

## Constraints observed

`SpiderFoot.csv` and `output_amogh/` are untracked local artifacts. They were
not altered by this assessment.

## Baseline conclusion

OSIRIS is currently a prototype with useful validation and XAI scaffolding. It
is **not cleared** for forensic evidence packaging, legal-review support,
external threat-intelligence dissemination, or unsupervised production use.

## Remediation progress

2026-07-16: graph domain parsing now uses the bundled public-suffix snapshot,
with no network fetch or user-cache write. Generated graph output is now a
self-contained static artifact rather than PyVis CDN output.

2026-07-16: `release_policy.py` became the single decision point for the
currently implemented PDF and MISP paths. A failed/missing audit, non-`REAL`
score mode, absent approved authorization, or absent integrity verification is
`BLOCKED`. PDF output is marked technical-review-only; MISP export raises an
error. This is not yet a complete release gate: authorization and integrity
artifacts still need to be implemented and attached to the pipeline.

2026-07-16: `case_authorization.py` adds a versioned authorization model and
scope/expiry/mode checks. `pipeline_with_spiderfoot()` now denies live
collection unless it receives an approved authorization that explicitly grants
active collection. Replay of an existing local fixture is still review-only;
case metadata and raw-evidence integrity have not yet been propagated through
that path.

2026-07-16: the replay pipeline now writes the original SpiderFoot fixture to
an append-only local `raw-evidence/` store before normalization. The record
includes a stable evidence ID, SHA-256, byte length, MIME type, source,
collector version, case/run ID and collection time; reads verify both hash and
length. This is only the local development store. S3/object-lock and normalized
assertions remain incomplete.

2026-07-16: local development Evidence Capsules now use an Ed25519-signed,
canonical JSON manifest and verify manifest signatures, hashes, file lengths,
case/run consistency, and missing/extra files. This is a local-development
mode only; it is not yet Cosign/keyless/KMS signing, RFC 3161 timestamping,
or in-toto attestation.

2026-07-16: `osiris.py` now exposes local-development key generation, capsule
build, and `osiris verify PATH`, including JSON output and non-zero verification
failure. `pyproject.toml` now states the Python 3.12 policy and package groups;
the dependency lock/security/lint/type/coverage CI work remains incomplete.

2026-07-16: default stub dossiers no longer emit OCEAN psychology or ideology.
The operational schema treats them as optional legacy/experimental fields, and
the deterministic scorer drops feature names in either category. Legacy parsing
remains supported, but ethical/legal methodology approval and an explicitly
enabled experimental profile are still required before any such research use.

2026-07-16: case/run IDs are now added to raw scans, dossiers, explanation
cards, reports, lineage and PROV-O output. Legacy fixture replay receives the
explicit `UNAUTHORIZED-LEGACY` case ID and remains blocked by release policy.
Graph/dashboard/capsule integration still needs a complete artifact-wide ID
consistency verifier before this requirement can be considered complete.

2026-07-16: the standalone dashboard now applies a restrictive CSP and escapes
profile timestamps as well as other displayed attacker-controlled strings. It
also coerces untrusted numeric display values rather than interpolating them.
This is source-level rendering coverage; automated offline browser tests remain
to be added.

2026-07-16: audit gating now rejects an explanation unless its displayed score
matches exactly and the dossier score reconstructs from declared intercept plus
signed contributions (including the declared raw total when provided). This
improves the existing deterministic scorer path; source assertion IDs and
release-policy checks for all remaining exports still need integration.

2026-07-16: synthetic fairness testing was redesigned as a matched
counterfactual for non-evidentiary identity display text. It preserves all
risk features and marks a test `INVALID_TEST` if evidence mutates. Domain and
geo-temporal changes are excluded from this fairness test because they may be
legitimate operational evidence. This remains a synthetic single-dossier test,
not a population-level fairness claim.

2026-07-16: `chain_of_custody.py` now provides append-only, hash-linked
custody events for collection, verification, transfer and related actions.
Historical changes break verification. Event signatures are represented but
local-development signing, legal-hold workflows, and capsule integration are
still pending.
