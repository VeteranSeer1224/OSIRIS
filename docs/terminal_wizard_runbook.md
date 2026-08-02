# OSIRIS terminal investigator runbook

OSIRIS is operated entirely in a terminal. The recommended interface is the
guided wizard:

```bash
osiris
```

No investigator needs to know or manually enter pipeline, SpiderFoot, graph,
LLM, report, export, or capsule commands. `python osiris.py` is equivalent when
the package entry point has not been installed.

## Start-to-finish guided workflow

1. Run `osiris` and select **System preflight**. Resolve every `FAIL` using the
   remediation printed beside it.
2. Select **Create a new case**, or **Import and validate a case JSON file**.
   For a new case, enter the case ID, title, lawful purpose,
   jurisdiction, investigator identity, organization, exact domain/IP targets,
   retention policy, handling marking, and optional source references/files.
3. Create an authorization draft. Choose passive/replay or active collection,
   enter its reference and validity period, and record exclusions.
4. In **Authorization and human verification**, select **Record human
   approval**. Supply the signed/approved source document, approver identity,
   exact authority phrase, and scope-review confirmation. OSIRIS copies and
   hashes the document; approval is not inferred.
5. Select **Verify authorization**. Active collection remains unavailable if
   the artifact is draft, expired, out of scope, altered, or passive-only.
6. Select **Run investigation pipeline**. Choose an authorized target and
   either live SpiderFoot, a bundled offline fixture, or a JSON/CSV replay. For live collection, choose a
   bounded profile/module override and timeout. Choose dry, OpenRouter, or
   Ollama analysis, then graph/PDF/dashboard options. Active collection and a
   potentially paid OpenRouter call each require their own human confirmation.
7. Review the confirmation and start. Each stage prints a progress bar. Ctrl+C
   asks the collector to abort, cleans up its worker, and records `CANCELLED`.
8. Review the final four labels: technical status, XAI audit status, release
   status, and output class. `REVIEW_ONLY`/`BLOCKED` output must not be
   disseminated.
9. Use **Retry a failed or cancelled run** after correcting the reported
   problem. Retry creates a new isolated run and links it to the original. A
   validated replay input is reused; after live collection completes, its
   preserved collector checkpoint is replayed rather than scanning again.
10. Use **Evaluate release** only when an external trusted Ed25519 public key
    and signature over canonical authorization JSON are available. STIX/MISP
    exports are written only after the typed release context passes.
11. Use **Build or verify an Evidence Capsule**. A capsule accepts only the
    explicit artifact allowlist and fails verification for extra, missing,
    changed, secret, private-key, or symlinked content.

## Case layout

```text
data/live_case/cases/CASE-ID/
├── case.json
├── authorization/
│   ├── authorization.json
│   ├── approval-record.json
│   └── source/
├── inputs/
├── run-records/
│   └── TIMESTAMP-ID.json
├── runs/
│   └── TIMESTAMP-ID/
├── releases/
└── capsules/
```

Run artifacts are built in a hidden staging directory and renamed into
`runs/TIMESTAMP-ID/` only after success. A failed run leaves no partially
published artifact directory; its diagnostic and retry settings remain in
`run-records/`.

Important artifacts include raw content-addressed evidence, `raw_scan.json`,
`dossier.json`, graph/dashboard output when selected, explanation cards,
fairness and robustness reports, `report.json`, `collection-status.json`,
`chain-of-custody.jsonl`, `legal_draft.txt`, `provenance.jsonld`, final
`lineage.json`, `run-summary.json`, and `release-decision.json`.

The legal draft is conspicuously review-only and requires completion and
signature by the responsible person, forensic expert, and legal counsel.

## Automation equivalents

The commands below use the same Python service layer as the wizard. They are
for controlled automation; the wizard remains the normal human workflow.

```bash
osiris --json preflight
osiris --json case list
osiris --json case show CASE-ID
osiris --json run list CASE-ID
```

Discover full argument descriptions without invoking a scan:

```bash
osiris --help
osiris case create --help
osiris authorization draft --help
osiris authorization approve --help
osiris run start --help
osiris release --help
osiris capsule --help
```

`--json` may appear anywhere. Exit codes are `0` for success, `2` for invalid
input/artifact failure, `3` for failed preflight, `4` for a blocked typed
release, and `130` for investigator cancellation.

## LLM and Explabox behavior

OpenRouter mode defaults to `openai/gpt-oss-120b`. The LLM receives only a
bounded normalized context; raw collector records are not sent. It produces
evidence-bound narrative fields only. Risk features, weights, score, score
level, evidence sufficiency, and abstention are deterministic server-side
outputs. OCEAN, ideology, protected-class, intent, and guilt inference are not
part of the operational schema.

Explabox is used only for cohort descriptives when it imports successfully.
Per-dossier attribution and the fallback path are deterministic, and artifacts
state which backend was active. Fairness is inconclusive when sample evidence
is insufficient. Robustness requires bounded score delta, no decision flip,
and at least 50% feature-ranking stability.

## Operational limitations

- OSIRIS does not establish source truth, guilt, identity, legal advice, or
  admissibility.
- Live SpiderFoot depends on the pinned local checkout, its optional services,
  network availability, rate limits, and configured API credentials.
- A local-development capsule key is not a production KMS identity, revocation
  system, or trusted timestamp.
- Additional source files/references are preserved and recorded in the run
  manifest; only validated SpiderFoot JSON/CSV is normalized into the current
  evidence graph.
- A dry run uses deterministic stub narrative output and is always review-only.
- Typed release can remain blocked even with a valid signature when fairness,
  robustness, evidence, provenance, authorization, or real-score requirements
  are not satisfied.
