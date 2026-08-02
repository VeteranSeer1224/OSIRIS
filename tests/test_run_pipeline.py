import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from release_policy import ReleaseBlockedError
import run_pipeline
from run_pipeline import pipeline_from_existing_scan, pipeline_with_spiderfoot
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

    sf_file = tmp_path / "source" / "sf_output.json"
    sf_file.parent.mkdir()
    with open(sf_file, "w") as f:
        json.dump(sf_data, f)

    results = pipeline_from_existing_scan(
        target="example.com",
        spiderfoot_json=str(sf_file),
        output_dir=str(tmp_path / "run"),
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
    sf_file = tmp_path / "source" / "sf_output.json"
    sf_file.parent.mkdir()
    sf_file.write_text(json.dumps([
        {"type": "DOMAIN_NAME", "data": "example.com", "module": "sfp_test"}
    ]), encoding="utf-8")

    with pytest.raises(ReleaseBlockedError, match="MISP export is prohibited"):
        pipeline_from_existing_scan(
            target="example.com",
            spiderfoot_json=str(sf_file),
            output_dir=str(tmp_path / "run"),
            do_export_misp=True,
            mind_dry_run=True,
            skip_graph=True,
        )


def test_active_authorization_survives_spiderfoot_pipeline(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    authorization = {
        "schema_version": "1.0", "case_id": "CASE-ACTIVE", "title": "Active test",
        "purpose": "authorized fixture", "jurisdiction": "IN",
        "created_at": now.isoformat(), "created_by": "tester",
        "authorization_reference": "AUTH-ACTIVE",
        "authorization_document_hash": "sha256:" + "a" * 64,
        "allowed_collection_modes": ["active"], "active_scanning_authorized": True,
        "authorized_targets": ["example.test"], "excluded_targets": [],
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "data_retention_policy": "test", "handling_marking": "TLP:CLEAR",
        "approvers": ["approver"], "status": "APPROVED",
    }
    auth_path = tmp_path / "authorization.json"
    auth_path.write_text(json.dumps(authorization), encoding="utf-8")

    def fake_scan(target, output_file, modules=None, use_case=None, timeout_seconds=900):
        Path(output_file).write_text(json.dumps([
            {"type": "DOMAIN_NAME", "data": target, "module": "fixture"}
        ]), encoding="utf-8")
        return output_file

    monkeypatch.setattr(run_pipeline, "run_spiderfoot_scan", fake_scan)
    results = pipeline_with_spiderfoot(
        "example.test", tmp_path / "output", skip_graph=True,
        case_authorization_path=auth_path,
    )
    report = json.loads(Path(results["report"]).read_text(encoding="utf-8"))
    lineage = json.loads(Path(results["lineage"]).read_text(encoding="utf-8"))
    assert report["report_metadata"]["case_id"] == "CASE-ACTIVE"
    assert report["case_authorization"]["case_id"] == "CASE-ACTIVE"
    assert lineage["case_id"] == "CASE-ACTIVE"


def test_pipeline_reports_stage_progress(tmp_path):
    sf_file = tmp_path / "source.json"
    sf_file.write_text(json.dumps([
        {"type": "DOMAIN_NAME", "data": "progress.test", "module": "fixture"}
    ]), encoding="utf-8")
    events = []
    pipeline_from_existing_scan(
        "progress.test", sf_file, tmp_path / "run", mind_dry_run=True,
        skip_graph=True, progress_callback=lambda stage, percent, detail: events.append(
            (stage, percent, detail)
        ),
    )
    assert events[0][0] == "authorization"
    assert events[-1][:2] == ("complete", 100)
    assert {event[0] for event in events} >= {"collection", "analysis", "explainability", "reporting"}
