# Project OSIRIS 

**Open-Source Intelligence & Reasoning Investigative System**

OSIRIS is a five-stage, open-source OSINT pipeline scoped for general
intelligence and threat assessment. It automates authorized evidence
collection, profiling, relationship visualization, and reviewable rationale.

## 🏗️ System Architecture

OSIRIS is organized as a linear pipeline whose stages communicate through
versioned JSON schemas.

| Stage | Module Name | Function | Reference Tool |
| :--- | :--- | :--- | :--- |
| **0** | **OSIRIS-Foundation** | Ethics gate, environment setup, scope authorization. | Python venv, DISCLAIMER.md |
| **1** | **OSIRIS-Sense** | Automated multi-source OSINT ingestion. | SpiderFoot |
| **2** | **OSIRIS-Mind** | AI-assisted profiling and risk scoring. | LLM API or local Ollama |
| **3** | **OSIRIS-Web** | Entity-relationship graph construction and visualization. | NetworkX + Pyvis |
| **4** | **OSIRIS-Conscience**| Explainability and fairness/robustness audit. | Explabox |
| **5** | **OSIRIS-Report** | Review-only PDF dossier and gated structured export. | WeasyPrint, MISP JSON |

## 🚀 Prerequisites & Installation

* **Environment:** Python 3.12 on Linux or WSL2.
* **Repository Location:** On WSL2, clone into the Linux filesystem rather than
  `/mnt/c/` to avoid filesystem overhead.
* **System Dependencies:** Run `setup.sh` to install WeasyPrint prerequisites.
* **Python Dependencies:** Run `./setup.sh` for the complete pinned environment,
  including the reviewed SpiderFoot revision and its compatibility dependencies.

## 🏃 Running the Pipeline

### Terminal investigator wizard (recommended)

Start OSIRIS with one command:

```bash
osiris
```

`python osiris.py` and `osiris wizard` are equivalent. The terminal wizard
handles the complete operator workflow without requiring pipeline commands:

1. Create or open a persistent case.
2. Record investigator, scope, jurisdiction, retention, handling and sources.
3. Create a fail-closed authorization draft.
4. Copy and hash the approved source document and record a human attestation.
5. Verify approval integrity, scope, collection mode and expiry.
6. Select live SpiderFoot or an existing JSON/CSV export.
7. Select OpenRouter, Ollama or offline dry-run analysis.
8. Run the stages with terminal progress and save every result in the case.
9. Build and verify signed Evidence Capsules from completed runs.

Case data is stored under `data/live_case/cases/<case-id>/` and is ignored by
Git. Every run has its own `runs/<timestamp-id>/run.json`, including status,
settings, results or the failure diagnostic. OpenRouter keys are requested with
hidden input only when needed; the investigator can keep the key in memory or
save it to the gitignored `.env` with owner-only permissions.

Human approval is an explicit checkpoint. The wizard does not infer authority,
and active collection cannot start without an approved, unexpired scope plus a
matching copied authorization document and approval-record hash. This records
an operator attestation; organizations requiring cryptographic identity or
countersignature must add their approved signing workflow.

### Evidence Capsule verification (local development)

The current local-development capsule flow is signed with an Ed25519 key and
fails closed if a file is added, removed, or changed:

```bash
osiris capsule keygen local-dev.pem --public-key trusted-public.pem
osiris capsule build --source outputs/ --output OSIRIS-Evidence-Capsule/ \
  --key local-dev.pem
osiris verify OSIRIS-Evidence-Capsule/ --trusted-key trusted-public.pem
```

This is not a legal-admissibility claim and is not a production Cosign/KMS
integration. See `docs/audits/baseline_findings.md` for current limitations.

The full pipeline runs all five stages in order:

**Sense → Mind → Web → Conscience → Report**

```bash
python run_pipeline.py \
  --target example.com \
  --input samples/spiderfoot_full.json \
  --output-dir outputs/ \
  --export-pdf \
  --export-misp
```

By default Stage 2 uses **dry-run** mode (offline stub dossier, no LLM API call). Pass `--mind-live` to invoke a real LLM backend.

### OpenRouter with `openai/gpt-oss-120b`

Copy `.env.example` to `.env`, add your OpenRouter key as `OPENROUTER_API_KEY`, then run Stage 2 live with the OpenRouter backend. The repository-local `.env` is loaded automatically and is ignored by Git; an environment variable takes precedence over `.env`.

```bash
python run_pipeline.py \
  --target example.com \
  --input samples/spiderfoot_small.json \
  --output-dir outputs/ \
  --mind-live \
  --mind-backend openrouter
```

The default OpenRouter model is `openai/gpt-oss-120b`. Override it with `OPENROUTER_MODEL` in `.env` or `--mind-model provider/model` on the command line.

Skip graph generation with `--skip-graph` if needed.

### Stage 4 Only (Conscience)

Generate explanation cards and audit reports from an existing dossier:

```bash
python explanation_card_build.py \
  --input schemas/samples/sample_dossier.json \
  --output-dir outputs/
```

Outputs:

| Artifact | Description |
| :--- | :--- |
| `explanation_cards.json` | Per-entity XAI cards (JSON only, no markdown) |
| `fairness_report.json` / `.md` | Synthetic perturbation fairness audit |
| `robustness_report.json` / `.md` | Structural perturbation robustness audit |

### Expected Inputs (Stage 4)

- **Primary:** `dossier.json` from OSIRIS-Mind (Contract 2)
- **Required fields:** `target`, `profile`, `risk_score`, `risk_features`
- **Optional:** `executive_summary`, `insufficient_data_flags`, `risk_level`

### Backend Selection

Stage 4 auto-selects an explainability backend:

1. **ExplaboxBackend** — used when the `explabox` Python package is installed
2. **FallbackBackend** — deterministic signed-weight attribution (always available)

Force fallback: `USE_EXPLABOX_BACKEND=0 python explanation_card_build.py ...`

The rest of the pipeline does not depend on which backend is active.

### Limitations

- Fairness testing uses **synthetic perturbation** only (name/region/domain swaps); no protected-class classifiers
- Robustness testing perturbs dossier structure locally; no adversarial ML attacks
- Explanations are generated only from dossier fields — no invented rationale
- Explabox integration is bounded: cohort descriptives when available; per-dossier attribution uses signed weights

## 🔄 Data Flow & Shared Contracts

The system passes data between stages using strict JSON contracts. The
execution flow is:

`OSIRIS-Sense` → `raw_scan.json` → `OSIRIS-Mind` → `dossier.json` →
`OSIRIS-Conscience` → `explanation_cards.json` → `OSIRIS-Report` →
review-only `final_report.pdf`; structured export is release-gated.

**Note on Stage 3 (Graph Intelligence)**: The OSIRIS-Web graph module directly consumes `raw_scan.json` (rather than `dossier.json`) to visualize the raw infrastructure and identity relationships immediately after ingestion.

## ⚖️ Ethical Safeguards & Rules of Engagement

Strict ethical scoping is a hard prerequisite. Before running Stage 1,
operators must acknowledge the `DISCLAIMER.md`.

* **Authorized Targets Only:** Targets require explicit, current authorization.
* **No Private Profiling:** Do not target non-consenting private individuals.
* **Respect Boundaries:** Respect terms, rate limits, and collection constraints;
  do not bypass credentials or authentication.
* **Mandatory XAI Audit:** Missing, failed, or inconclusive audit controls block
  dissemination.
