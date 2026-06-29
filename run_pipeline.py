import argparse
import json
import subprocess
import sys
from pathlib import Path

from sense_clean import generate_raw_scan
from report_build import build_report
from schema_validation import (
    validate_raw_scan,
    validate_report
)


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
    output_dir
):
    output_dir = ensure_dir(output_dir)

    raw_scan = generate_raw_scan(
        target,
        spiderfoot_json
    )

    validate_raw_scan(raw_scan)

    raw_scan_path = (
        output_dir / "raw_scan.json"
    )

    save_json(
        raw_scan,
        raw_scan_path
    )

    report = build_report(raw_scan)

    validate_report(report)

    report_path = (
        output_dir / "report.json"
    )

    save_json(
        report,
        report_path
    )

    return {
        "raw_scan": str(raw_scan_path),
        "report": str(report_path)
    }


def pipeline_with_spiderfoot(
    target,
    output_dir
):
    output_dir = ensure_dir(output_dir)

    spiderfoot_output = (
        output_dir /
        "spiderfoot_output.json"
    )

    run_spiderfoot_scan(
        target,
        spiderfoot_output
    )

    return pipeline_from_existing_scan(
        target,
        spiderfoot_output,
        output_dir
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

    args = parser.parse_args()

    try:
        if args.input:
            results = pipeline_from_existing_scan(
                args.target,
                args.input,
                args.output_dir
            )
        else:
            results = pipeline_with_spiderfoot(
                args.target,
                args.output_dir
            )

        print("\nPipeline completed successfully.\n")
        print(
            f"Raw Scan : {results['raw_scan']}"
        )
        print(
            f"Report   : {results['report']}"
        )

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