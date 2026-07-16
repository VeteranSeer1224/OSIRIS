import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from release_policy import ReleaseBlockedError
from run_pipeline import pipeline_from_existing_scan
from schema_validation import validate_explanation_cards


def test_pipeline_end_to_end_creates_review_only_output_for_stub_dossier(tmp_path):
    sf_data = [
        {
            "type": "DOMAIN_NAME",
            "data": "example.com",
            "module": "sfp_test"
        },
        {
            "type": "IP_ADDRESS",
            "data": "93.184.216.34",
            "module": "sfp_test"
        }
    ]

    sf_file = tmp_path / "sf_output.json"
    with open(sf_file, "w") as f:
        json.dump(sf_data, f)

    results = pipeline_from_existing_scan(
        target="example.com",
        spiderfoot_json=str(sf_file),
        output_dir=str(tmp_path),
        do_export_pdf=True,
        do_export_misp=False,
        mind_dry_run=True,
        skip_graph=False,
    )

    expected_keys = {
        "raw_scan",
        "dossier",
        "explanation_cards",
        "fairness_report",
        "fairness_report_json",
        "robustness_report",
        "robustness_report_json",
        "report",
        "graph",
        "pdf_report",
    }
    assert expected_keys.issubset(set(results.keys()))

    for key in results:
        assert Path(results[key]).exists(), f"Missing output: {key}"

    with open(results["explanation_cards"]) as f:
        cards = json.load(f)
    validate_explanation_cards(cards)

    with open(results["report"]) as f:
        report = json.load(f)
    assert "xai_audit" in report
    assert report["xai_audit"]["card_count"] >= 1
    assert report["risk_assessment"]["source"] == "OSIRIS-Mind"

    assert report["release_decision"]["status"] == "BLOCKED"
    assert "misp_export" not in results
    assert Path(results["raw_evidence"]).exists()
    assert Path(results["raw_evidence_metadata"]).exists()
    assert report["evidence_integrity"]["status"] == "PASS"
    assert report["report_metadata"]["case_id"] == "UNAUTHORIZED-LEGACY"
    lineage = json.loads(Path(results["lineage"]).read_text(encoding="utf-8"))
    assert report["report_metadata"]["run_id"] == lineage["run_id"]


def test_stub_pipeline_cannot_export_misp(tmp_path):
    sf_file = tmp_path / "sf_output.json"
    sf_file.write_text(json.dumps([
        {"type": "DOMAIN_NAME", "data": "example.com", "module": "sfp_test"}
    ]), encoding="utf-8")

    with pytest.raises(ReleaseBlockedError, match="MISP export is prohibited"):
        pipeline_from_existing_scan(
            target="example.com",
            spiderfoot_json=str(sf_file),
            output_dir=str(tmp_path),
            do_export_misp=True,
            mind_dry_run=True,
            skip_graph=True,
        )
