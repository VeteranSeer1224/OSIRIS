# Project OSIRIS 

[cite_start]**Open-Source Intelligence & Reasoning Investigative System** [cite: 236]

[cite_start]OSIRIS is a five-stage, fully open-source OSINT pipeline scoped for the General Intelligence & Threat Assessment domain[cite: 300, 302]. [cite_start]It automates evidence collection, AI-based profiling, relationship-graph visualization, and—critically—produces an explainable, audit-ready rationale for every AI-generated finding[cite: 239, 302].

## 🏗️ System Architecture

[cite_start]OSIRIS is organized as a linear pipeline where each stage is a separately deployable module that communicates exclusively through versioned JSON schemas[cite: 256, 257]. 

| Stage | Module Name | Function | Reference Tool |
| :--- | :--- | :--- | :--- |
| **0** | **OSIRIS-Foundation** | [cite_start]Ethics gate, environment setup, scope authorization[cite: 259]. | [cite_start]Python venv, DISCLAIMER.md[cite: 259]. |
| **1** | **OSIRIS-Sense** | [cite_start]Automated multi-source OSINT ingestion[cite: 260]. | [cite_start]SpiderFoot[cite: 260]. |
| **2** | **OSIRIS-Mind** | [cite_start]Autonomous AI profiling and risk scoring[cite: 260]. | [cite_start]LLM (API or local via Ollama)[cite: 260]. |
| **3** | **OSIRIS-Web** | [cite_start]Entity-relationship graph construction & visualization[cite: 261]. | [cite_start]NetworkX + Pyvis[cite: 262]. |
| **4** | **OSIRIS-Conscience**| [cite_start]Explainability and fairness/robustness audit[cite: 262]. | [cite_start]Explabox[cite: 262]. |
| **5** | **OSIRIS-Report** | [cite_start]Court-style PDF dossier and structured export[cite: 263]. | [cite_start]WeasyPrint, MISP JSON[cite: 263]. |

## 🚀 Prerequisites & Installation

* [cite_start]**Environment:** Development is standardized on WSL2 (Ubuntu) with Python 3.11[cite: 301].
* [cite_start]**Repository Location:** It is highly recommended to clone the repository directly into the Linux filesystem (`~/osiris`) rather than `/mnt/c/` to avoid severe performance issues during Git and Pip operations[cite: 231, 232].
* [cite_start]**System Dependencies:** You must run the `setup.sh` script to install system requirements, including WeasyPrint prerequisites (`libpango-1.0-0` and `libpangocairo-1.0-0`), before attempting to install the Python packages[cite: 230, 231].
* **Python Dependencies:** Run `pip install -r requirements.txt`.

## 🏃 Running the Pipeline

You can run the full pipeline in one command using `run_pipeline.py`. This script handles ingestion, validation, and Stage 5 reporting (PDF and MISP export).

```bash
python run_pipeline.py --target example.com --input schemas/samples/sample_raw_scan.json --output-dir outputs/ --export-pdf --export-misp
```

## 🔄 Data Flow & Shared Contracts

[cite_start]The system passes data between stages using strict JSON contracts, which allows all team members to develop their modules concurrently[cite: 257, 265]. The execution flow is as follows:

[cite_start]`OSIRIS-Sense` → `raw_scan.json` → `OSIRIS-Mind` → `dossier.json` → `OSIRIS-Conscience` → `explanation_cards.json` → `OSIRIS-Report` → `final_report.pdf` + `misp_export.json`[cite: 266].

**Note on Stage 3 (Graph Intelligence)**: The OSIRIS-Web graph module directly consumes `raw_scan.json` (rather than `dossier.json`) to visualize the raw infrastructure and identity relationships immediately after ingestion.

## ⚖️ Ethical Safeguards & Rules of Engagement

[cite_start]Because OSIRIS models law-enforcement intelligence tooling, strict ethical scoping is a hard prerequisite[cite: 275]. [cite_start]Before running Stage 1, all operators must acknowledge and sign the `DISCLAIMER.md`[cite: 280]. 

* [cite_start]**Authorized Targets Only:** All test targets must be infrastructure owned by the project team, explicitly designated public test sandboxes, or already-public figures who have consented to OSINT-methodology research[cite: 277].
* [cite_start]**No Private Profiling:** No real, non-consenting private individual is targeted, profiled, or scored at any point in development, testing, or demonstration[cite: 278].
* [cite_start]**Respect Boundaries:** All ingestion respects `robots.txt`, platform terms of service, and rate limits[cite: 279]. [cite_start]No credential-based or authentication-bypassing collection is performed[cite: 279].
* [cite_start]**Mandatory XAI Audit:** The XAI layer (Stage 4) is treated as a mandatory gate, not an optional enhancement[cite: 281]. [cite_start]No finding reaches the final report without an attached explanation and fairness check[cite: 281].