# Technical Review Remediation Report

Date: 2026-07-29  
Source review: `OSIRIS_Deep_Technical_XAI_UI_and_Legal_Readiness_Audit.pdf`

## Outcome

This remediation pass corrected the audit's reproducible scoring-authority,
artifact-contract, timestamp-truthfulness, and SpiderFoot import-boundary
defects. The repository now passes its source compilation, full Python test,
lint, type, Bandit, frontend typecheck, and frontend production-build gates.

This is **not** a production, court-ready, complete-XAI, or live-collection
approval. The audit's broader forensic, governance, data-minimisation,
calibration, and operational-release requirements remain open and must not be
represented as complete.

## Changes delivered

| Audit item | Status | Implemented result | Commit |
| --- | --- | --- | --- |
| P0-01, model-controlled weights | Fixed | Only the versioned `DEFAULT_WEIGHTS` registry can supply a score weight. | `a692146` |
| P0-02, duplicate feature inflation | Fixed | Duplicate scoring features fail validation; they cannot inflate score or sufficiency. | `a692146` |
| P0-03, unknown/malformed values becoming zero | Fixed | Unsupported, boolean, non-numeric, and non-finite scoring values now fail closed. | `a692146` |
| P1-01, loose/typed dossier drift | Fixed | The pipeline validates `RawScan` and `Dossier` with the canonical Pydantic models; metadata now includes `model_name`. | `f441041` |
| P1-07, fabricated event chronology | Fixed | Events retain separate `observed_at` and `collected_at`; missing source time remains null. | `f441041` |
| P0-04, SpiderFoot import crash | Improved, not operationally closed | A bad optional dependency no longer crashes module import; live collection fails before network activity with a precise diagnostic. The installed local SpiderFoot runtime still has an OpenSSL compatibility failure and is not approved for live use. | `10bd9f9` |
| Static quality regression | Fixed | The collector-boundary code typechecks cleanly. | `1cbd69c` |

The focused commits were intentionally kept separate so they can be reviewed,
reverted, or cherry-picked independently.

## Verification evidence

Executed on the repository's Python 3.12 virtual environment unless noted:

| Gate | Result |
| --- | --- |
| Source-only Python compilation | Pass |
| Full test suite | `153 passed in 21.42s` |
| Ruff | Pass |
| MyPy | `Success: no issues found in 23 source files` |
| Bandit (excluding virtualenv, build, tests, vendored SpiderFoot) | Pass |
| Frontend lint/typecheck | Pass |
| Frontend production build | Pass with Next.js 16.2.12 |
| `pip-audit -r requirements.txt --strict` | Pass |
| `npm audit --omit=dev --audit-level=high` | Pass |

`python -m compileall -q .` is not a valid repository source gate in this
checkout because it descends into `.venv` and encounters a tab-indentation
defect in a third-party package. Source compilation was therefore scoped to
the project source and tests. The same local SpiderFoot dependency stack also
currently raises an OpenSSL compatibility error on import; the collector is
explicitly blocked rather than silently degraded.

## Remaining material gaps

The following audit conclusions remain valid and are deliberately not hidden
by the fixes above:

- **Evidence provenance:** entity IDs are not yet claim-level references to
  exact raw-record offsets/bytes, parser versions, transformations, source
  reliability, corroboration, freshness, or conflicts (P0-06, P1-08/P1-09).
- **Release path:** `ReleaseContext` is fail-closed, but the normal pipeline
  does not yet construct a fully signed, immutable, independently attested
  release package (P0-05/P0-07/P0-10/P1-10/P1-11/P1-18).
- **XAI/model validity:** deterministic arithmetic is now protected from
  model-supplied scoring inputs, but there is no labelled calibrated model,
  held-out evaluation, real Explabox examination, or complete fairness and
  robustness path (P0-08/P0-09 and P1-02 through P1-06).
- **External LLM governance:** the OpenRouter integration lacks the required
  request minimisation/redaction policy, strict provider response schema, and
  complete request/response provenance (P1-12/P1-13).
- **Collector/supply chain:** SpiderFoot is neither pinned as a supported
  reproducible dependency nor live-contract tested. `setup.sh` still uses an
  unpinned clone and an unsafe remote installer (P1-14/P1-15).
- **Exports and legal readiness:** STIX/MISP semantics, jurisdiction-specific
  certification, trusted time, signatures, object lock, RBAC, retention,
  observability, and independent legal/forensic review remain outstanding.
- **UI validation:** the new frontend builds and types cleanly, but browser
  automation, accessibility checks, responsive snapshots, and an
  evidence-drill-down data contract are still required before relying on it
  for an analyst workflow (P2-05/P2-08).

## Current go/no-go position

| Use case | Decision |
| --- | --- |
| Offline synthetic/demo pipeline | Conditional GO, with review-only labels and no dissemination claim |
| Frontend preview | Conditional GO for demonstration only |
| Live SpiderFoot collection | NO-GO until a pinned, clean-install collector contract passes |
| Genuine model/XAI claim | NO-GO until calibrated model and real evaluation evidence exist |
| Controlled analyst pilot, legal evidence, courtroom, or production | NO-GO |

The appropriate present description remains: **an evidence-linked,
fail-closed AI-assisted OSINT auditing research prototype**.
