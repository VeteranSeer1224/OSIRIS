import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sense_clean import generate_raw_scan
from report_build import build_report, export_pdf, export_misp
from schema_validation import (
    validate_raw_scan,
    validate_report,
    validate_explanation_cards,
)
from explanation_card_build import BuildConfig, build_artifacts, write_outputs
from graph_build import build_graph, render_graph
from case_authorization import (
    AuthorizationError,
    CollectionMode,
    load_case_authorization,
    validate_collection,
)
from evidence_store import LocalEvidenceStore
from provenance import build_provenance

from mind.mind_profile import profile  # noqa: E402


class PipelineError(Exception):
    pass


def ensure_dir(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)




def check_ethics_gate(disclaimer_path=None):
    """Stage 0: Verify ethics gate disclaimer acknowledgment."""
    if disclaimer_path is None:
        disclaimer_path = Path(__file__).resolve().parent / "DISCLAIMER.md"
    else:
        disclaimer_path = Path(disclaimer_path)
    if not disclaimer_path.exists():
        raise PipelineError("Stage 0 Ethics Gate failed: DISCLAIMER.md not found.")
    content = disclaimer_path.read_text(encoding="utf-8")
    if "- [x]" not in content and "- [X]" not in content:
        raise PipelineError("Stage 0 Ethics Gate failed: DISCLAIMER.md must be acknowledged by team contributors.")
    return content


def run_spiderfoot_scan(target, output_file, modules=None, use_case=None):
    """
    Helper to run SpiderFoot scan via spiderfoot_runner.
    """
    try:
        import spiderfoot_runner
        spiderfoot_runner.run_scan(target, output_file, modules=modules, use_case=use_case)
        return output_file
    except ImportError:
        pass

    runner_path = Path(__file__).resolve().parent / "spiderfoot_runner.py"
    command = [
        sys.executable,
        str(runner_path),
        target,
        str(output_file)
    ]
    if modules:
        command.extend(["-m", modules])
    if use_case:
        command.extend(["-u", use_case])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise PipelineError(
            f"SpiderFoot execution failed:\n{result.stderr}"
        )

    return output_file


def pipeline_from_existing_scan(
    target,
    spiderfoot_json,
    output_dir,
    do_export_pdf=False,
    do_export_misp=False,
    mind_dry_run=True,
    skip_graph=False,
    do_export_dashboard=False,
    case_authorization_path=None,
):
    """Run Sense → Mind → Web → Conscience → Report."""
    check_ethics_gate()
    output_dir = ensure_dir(output_dir)
    run_id = str(uuid.uuid4())
    run_timestamp = datetime.now(timezone.utc).isoformat()
    authorization = None
    if case_authorization_path:
        try:
            authorization = load_case_authorization(case_authorization_path)
            validate_collection(authorization, target, CollectionMode.PASSIVE)
        except AuthorizationError as exc:
            raise PipelineError(f"Case authorization failed: {exc}") from exc
    case_id = authorization.case_id if authorization else "UNAUTHORIZED-LEGACY"
    evidence_store = LocalEvidenceStore(output_dir)
    raw_record = evidence_store.preserve(
        Path(spiderfoot_json).read_bytes(), case_id=case_id, run_id=run_id,
        source_type="spiderfoot_export", source_identifier=str(spiderfoot_json),
        mime_type="application/json",
    )
    evidence_store.verify(raw_record)

    raw_scan = generate_raw_scan(
        target,
        spiderfoot_json
    )
    raw_scan["case_id"] = case_id
    raw_scan["run_id"] = run_id

    validate_raw_scan(raw_scan)

    raw_scan_path = output_dir / "raw_scan.json"
    save_json(raw_scan, raw_scan_path)

    dossier_path = output_dir / "dossier.json"
    dossier = profile(
        raw_scan_path=str(raw_scan_path),
        output_path=str(dossier_path),
        dry_run=mind_dry_run,
    )
    dossier["case_id"] = case_id
    dossier["run_id"] = run_id
    save_json(dossier, dossier_path)

    graph_path = None
    if not skip_graph:
        graph, timeline = build_graph(raw_scan)
        graph_path = output_dir / "graph.html"
        render_graph(
            graph,
            timeline,
            graph_path,
            title=f"OSIRIS-Web — {target}",
        )

    conscience_config = BuildConfig(
        input_path=dossier_path,
        output_dir=output_dir,
    )
    conscience_artifacts = build_artifacts(conscience_config)
    conscience_artifacts.explanation_cards["case_id"] = case_id
    conscience_artifacts.explanation_cards["run_id"] = run_id
    conscience_paths = write_outputs(conscience_artifacts, output_dir)
    validate_explanation_cards(conscience_artifacts.explanation_cards)

    explanation_cards = conscience_artifacts.explanation_cards
    report = build_report(
        raw_scan,
        dossier=dossier,
        explanation_cards=explanation_cards,
        case_authorization=(authorization.model_dump(mode="json") if authorization else None),
        evidence_integrity={"status": "PASS", "raw_evidence_ids": [raw_record.evidence_id]},
    )
    report["report_metadata"]["case_id"] = case_id
    report["report_metadata"]["run_id"] = run_id

    validate_report(report)

    report_path = output_dir / "report.json"
    save_json(report, report_path)

    results = {
        "raw_evidence": str(output_dir / raw_record.relative_path),
        "raw_evidence_metadata": str(
            (output_dir / raw_record.relative_path).with_suffix(
                (output_dir / raw_record.relative_path).suffix + ".metadata.json"
            )
        ),
        "raw_scan": str(raw_scan_path),
        "dossier": str(dossier_path),
        "explanation_cards": str(conscience_paths["explanation_cards"]),
        "fairness_report": str(conscience_paths["fairness_report"]),
        "fairness_report_json": str(conscience_paths["fairness_report_json"]),
        "robustness_report": str(conscience_paths["robustness_report"]),
        "robustness_report_json": str(conscience_paths["robustness_report_json"]),
        "report": str(report_path),
    }

    if graph_path is not None:
        results["graph"] = str(graph_path)

    if do_export_pdf:
        pdf_path = output_dir / "report.pdf"
        actual_pdf_path = export_pdf(report, pdf_path)
        results["pdf_report"] = str(actual_pdf_path)

    if do_export_misp:
        misp_path = output_dir / "misp_export.json"
        actual_misp_path = export_misp(report, misp_path)
        results["misp_export"] = str(actual_misp_path)

    # Compute artifact hashes for lineage
    artifact_hashes = {}
    for name, filepath in results.items():
        fp = Path(filepath)
        if fp.exists() and fp.is_file():
            artifact_hashes[fp.name] = hashlib.sha256(fp.read_bytes()).hexdigest()

    lineage = {
        "schema_version": "1.0",
        "run_id": run_id,
        "case_id": case_id,
        "raw_evidence": raw_record.__dict__,
        "generated_at": run_timestamp,
        "model_metadata": dossier.get("model_metadata", {}),
        "artifact_hashes": artifact_hashes,
    }
    lineage_path = output_dir / "lineage.json"
    save_json(lineage, lineage_path)
    results["lineage"] = str(lineage_path)

    provenance_path = output_dir / "provenance.jsonld"
    save_json(build_provenance(
        case_id=case_id, run_id=run_id, raw_evidence=raw_record.__dict__,
        artifacts=artifact_hashes,
    ), provenance_path)
    results["provenance"] = str(provenance_path)

    if do_export_dashboard:
        from xai_dashboard import generate_dashboard_html
        dashboard_path = output_dir / "xai_dashboard.html"
        generate_dashboard_html(raw_scan, dossier, explanation_cards, report, lineage, dashboard_path)
        results["xai_dashboard"] = str(dashboard_path)

    return results


def pipeline_with_spiderfoot(
    target,
    output_dir,
    do_export_pdf=False,
    do_export_misp=False,
    mind_dry_run=True,
    skip_graph=False,
    do_export_dashboard=False,
    modules=None,
    use_case=None,
    case_authorization_path=None,
):
    if not case_authorization_path:
        raise PipelineError(
            "Active SpiderFoot collection is disabled by default. Supply an approved "
            "--case-authorization file with explicit target scope and collection mode."
        )
    try:
        authorization = load_case_authorization(case_authorization_path)
        # SpiderFoot execution is active collection even when selected modules
        # are nominally passive: invoking it can make network requests.
        validate_collection(authorization, target, CollectionMode.ACTIVE)
    except AuthorizationError as exc:
        raise PipelineError(f"Case authorization failed: {exc}") from exc
    output_dir = ensure_dir(output_dir)

    spiderfoot_output = output_dir / "spiderfoot_output.json"

    run_spiderfoot_scan(
        target,
        spiderfoot_output,
        modules=modules,
        use_case=use_case,
    )

    return pipeline_from_existing_scan(
        target,
        spiderfoot_output,
        output_dir,
        do_export_pdf,
        do_export_misp,
        mind_dry_run,
        skip_graph,
        do_export_dashboard,
    )


def main():
    parser = argparse.ArgumentParser(
        description="OSIRIS Pipeline Runner"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target domain, IP, or organization"
    )

    parser.add_argument(
        "--input",
        help="Existing SpiderFoot JSON export"
    )

    parser.add_argument(
        "--case-authorization",
        help="Approved case-authorization JSON required for active SpiderFoot collection",
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="Pipeline output directory"
    )
    
    parser.add_argument(
        "--export-pdf",
        action="store_true",
        help="Generate a PDF report using WeasyPrint (or HTML fallback)"
    )
    
    parser.add_argument(
        "--export-misp",
        action="store_true",
        help="Export findings to MISP JSON format"
    )

    parser.add_argument(
        "--export-dashboard",
        action="store_true",
        help="Generate standalone XAI Analyst HTML Dashboard"
    )

    parser.add_argument(
        "--mind-live",
        action="store_true",
        help="Call a real LLM for Stage 2 (default: dry-run stub dossier)",
    )

    parser.add_argument(
        "--skip-graph",
        action="store_true",
        help="Skip Stage 3 graph.html generation",
    )

    parser.add_argument(
        "-m", "--modules",
        help="Comma-separated list of SpiderFoot modules to run (e.g., sfp_whois,sfp_dnsresolve)",
    )

    parser.add_argument(
        "-u", "--use-case",
        help="Select SpiderFoot modules by use case (osiris_fast, osiris_full, threat_intel, infrastructure, identity, vulnerabilities, footprint, passive, investigate, all)",
    )

    args = parser.parse_args()

    try:
        if args.input:
            results = pipeline_from_existing_scan(
                args.target,
                args.input,
                args.output_dir,
                args.export_pdf,
                args.export_misp,
                mind_dry_run=not args.mind_live,
                skip_graph=args.skip_graph,
                do_export_dashboard=args.export_dashboard,
                case_authorization_path=args.case_authorization,
            )
        else:
            results = pipeline_with_spiderfoot(
                args.target,
                args.output_dir,
                args.export_pdf,
                args.export_misp,
                mind_dry_run=not args.mind_live,
                skip_graph=args.skip_graph,
                do_export_dashboard=args.export_dashboard,
                modules=args.modules,
                use_case=args.use_case,
                case_authorization_path=args.case_authorization,
            )

        print("\nPipeline completed successfully.\n")
        print(f"Raw Scan          : {results.get('raw_scan')}")
        print(f"Dossier           : {results.get('dossier')}")
        print(f"Explanation Cards : {results.get('explanation_cards')}")
        if "graph" in results:
            print(f"Graph             : {results.get('graph')}")
        print(f"Report            : {results.get('report')}")
        if "pdf_report" in results:
            print(f"PDF               : {results.get('pdf_report')}")
        if "misp_export" in results:
            print(f"MISP              : {results.get('misp_export')}")
        if "lineage" in results:
            print(f"Lineage Manifest  : {results.get('lineage')}")
        if "xai_dashboard" in results:
            print(f"XAI Dashboard     : {results.get('xai_dashboard')}")

    except PipelineError as e:
        print(
            f"Pipeline Error: {e}",
            file=sys.stderr
        )
        sys.exit(1)

    except Exception as e:
        print(
            f"Unexpected Error: {e}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
