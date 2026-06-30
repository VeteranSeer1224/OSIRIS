import argparse
import json
import subprocess
import sys
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

_MIND_DIR = Path(__file__).resolve().parent / "mind"
if str(_MIND_DIR) not in sys.path:
    sys.path.insert(0, str(_MIND_DIR))
from mind_profile import profile  # noqa: E402


class PipelineError(Exception):
    pass


def ensure_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)




def run_spiderfoot_scan(target, output_file):
    """
    Optional helper if SpiderFoot is installed locally.
    """

    command = [
        "python",
        "spiderfoot_runner.py",
        target,
        str(output_file)
    ]

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
):
    """Run Sense → Mind → Web → Conscience → Report."""
    output_dir = ensure_dir(output_dir)

    raw_scan = generate_raw_scan(
        target,
        spiderfoot_json
    )

    validate_raw_scan(raw_scan)

    raw_scan_path = output_dir / "raw_scan.json"
    save_json(raw_scan, raw_scan_path)

    dossier_path = output_dir / "dossier.json"
    dossier = profile(
        raw_scan_path=str(raw_scan_path),
        output_path=str(dossier_path),
        dry_run=mind_dry_run,
    )

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
    conscience_paths = write_outputs(conscience_artifacts, output_dir)
    validate_explanation_cards(conscience_artifacts.explanation_cards)

    explanation_cards = conscience_artifacts.explanation_cards
    report = build_report(
        raw_scan,
        dossier=dossier,
        explanation_cards=explanation_cards,
    )

    validate_report(report)

    report_path = output_dir / "report.json"
    save_json(report, report_path)

    results = {
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

    return results


def pipeline_with_spiderfoot(
    target,
    output_dir,
    do_export_pdf=False,
    do_export_misp=False,
    mind_dry_run=True,
    skip_graph=False,
):
    output_dir = ensure_dir(output_dir)

    spiderfoot_output = output_dir / "spiderfoot_output.json"

    run_spiderfoot_scan(
        target,
        spiderfoot_output
    )

    return pipeline_from_existing_scan(
        target,
        spiderfoot_output,
        output_dir,
        do_export_pdf,
        do_export_misp,
        mind_dry_run,
        skip_graph,
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
        "--mind-live",
        action="store_true",
        help="Call a real LLM for Stage 2 (default: dry-run stub dossier)",
    )

    parser.add_argument(
        "--skip-graph",
        action="store_true",
        help="Skip Stage 3 graph.html generation",
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
            )
        else:
            results = pipeline_with_spiderfoot(
                args.target,
                args.output_dir,
                args.export_pdf,
                args.export_misp,
                mind_dry_run=not args.mind_live,
                skip_graph=args.skip_graph,
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