"""
Tests for OSIRIS Conference Readiness Audit Fixes
Verifies deterministic score reconstruction, paired sensitivity testing,
audit gate enforcement, XSS escaping, evidence IDs/provenance, and XAI dashboard generation.
"""

import html
import json
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from mind.mind_profile import _stub_dossier, score_from_features, DeterministicScorer
from explabox_wrapper import _perturb_fairness, _fairness_check, _predict_score
from report_build import _assert_explanation_gate, export_pdf, build_report, export_misp
from release_policy import ReleaseBlockedError
from sense_clean import generate_raw_scan
from run_pipeline import pipeline_from_existing_scan
from xai_dashboard import generate_dashboard_html


def test_score_reconstruction_exact():
    """Verify that sum(contribution_points) + intercept == risk_score exactly."""
    scan = {
        "target": "reconstruct.test",
        "entities": [
            {"type": "domain", "value": "reconstruct.test"},
            {"type": "ip", "value": "198.51.100.1"},
        ],
        "events": [
            {"date": "2026-01-01T00:00:00Z", "type": "breach_appearance", "entity": "admin@reconstruct.test", "source": "HIBP"},
            {"date": "2026-01-02T00:00:00Z", "type": "breach_appearance", "entity": "user@reconstruct.test", "source": "HIBP"},
        ]
    }
    dossier = _stub_dossier("reconstruct.test", scan)
    
    scoring_meta = dossier.get("scoring_metadata", {})
    intercept = scoring_meta.get("intercept", 15.0)
    contributions = scoring_meta.get("contributions", [])
    
    total_pts = intercept + sum(c.get("contribution_points", 0.0) for c in contributions)
    assert round(total_pts) == dossier["risk_score"]


def test_fairness_perturbation_preserves_evidence():
    """Matched counterfactual changes only non-evidentiary identity display text."""
    dossier = {
        "target": "fairness.test",
        "profile": {"identity": "Admin User at Corp Inc"},
        "risk_features": [
            {"feature": "breach_appearance_count", "value": 5, "normalized_value": 0.5, "weight": 20.0, "contribution_points": 10.0, "plain_language": "5 breach appearances"},
            {"feature": "domain_age_days", "value": 1000, "normalized_value": 0.2, "weight": -10.0, "contribution_points": -2.0, "plain_language": "Domain is 1000 days old"},
        ],
        "scoring_metadata": {"intercept": 15.0}
    }
    
    orig_score = _predict_score(dossier)
    perturbed = _perturb_fairness(dossier, "identity")
    pert_score = _predict_score(perturbed)
    
    assert orig_score == pert_score
    assert perturbed["risk_features"] == dossier["risk_features"]
    assert perturbed["_fairness_changed_fields"] == ["profile.identity"]


def test_audit_gate_failure_and_blocked_status():
    """Verify AuditGateResult status transitions across PASS, FAIL, and BLOCKED."""
    dossier = {
        "target": "gate.test",
        "risk_score": 50,
        "scoring_metadata": {
            "intercept": 15.0,
            "risk_score_raw": 50.0,
            "contributions": [{"contribution_points": 35.0}],
        }
    }
    
    # 1. BLOCKED when cards are missing/empty
    res_blocked = _assert_explanation_gate(dossier, [])
    assert res_blocked["status"] == "BLOCKED"
    assert any("No explanation card found" in c for c in res_blocked["failed_conditions"])
    
    # 2. FAIL when score discrepancy exceeds tolerance
    bad_card = {"cards": [{
        "entity": "gate.test",
        "risk_score": 90, # 40 point discrepancy vs dossier's 50
        "fairness_check": {"passed": True},
        "robustness_check": {"passed": True}
    }]}
    res_fail = _assert_explanation_gate(dossier, bad_card)
    assert res_fail["status"] == "FAIL"
    assert any("does not match dossier score" in c for c in res_fail["failed_conditions"])
    
    # 3. PASS when cards match exactly, reconstruct, and pass checks
    good_card = {"cards": [{
        "entity": "gate.test",
        "risk_score": 50,
        "fairness_check": {"passed": True},
        "robustness_check": {"passed": True}
    }]}
    res_pass = _assert_explanation_gate(dossier, good_card)
    assert res_pass["status"] == "PASS"
    assert not res_pass["failed_conditions"]


def test_audit_gate_rejects_nonreconstructable_score():
    dossier = {
        "target": "reconstruction.test", "risk_score": 50,
        "scoring_metadata": {"intercept": 15.0, "contributions": []},
    }
    cards = {"cards": [{
        "entity": "reconstruction.test", "risk_score": 50,
        "fairness_check": {"passed": True}, "robustness_check": {"passed": True},
    }]}
    result = _assert_explanation_gate(dossier, cards)
    assert result["status"] == "FAIL"
    assert any("reconstruction" in condition.lower() for condition in result["failed_conditions"])


def test_xss_safety_in_pdf_and_dashboard(tmp_path: Path):
    """Verify all user/target-controlled strings are escaped with html.escape in HTML/PDF outputs."""
    malicious_target = "<script>alert('XSS')</script>"
    report = {
        "report_metadata": {"target": malicious_target, "generated_at": "2026-07-14T00:00:00Z"},
        "summary": {"target": malicious_target, "executive_summary": "Summary with <img src=x onerror=alert(1)>"},
        "risk_assessment": {"score": 50, "level": "HIGH"},
        "findings": [],
        "events": [],
        "dossier_summary": {},
        "xai_audit": {"card_count": 0, "overall_fairness_passed": True, "overall_robustness_passed": True, "cards": []}
    }
    
    # PDF/HTML check (read as raw bytes; neither binary PDF nor HTML should contain unescaped script tags)
    out_pdf = tmp_path / "report.pdf"
    actual_path = export_pdf(report, out_pdf)
    content_bytes = actual_path.read_bytes()
    assert b"<script>alert('XSS')</script>" not in content_bytes
    
    # Dashboard check (plaintext HTML file)
    dashboard_html = tmp_path / "dashboard.html"
    generate_dashboard_html(
        raw_scan={"target": malicious_target, "entities": []},
        dossier={"target": malicious_target, "risk_score": 50, "risk_level": "HIGH"},
        explanation_cards={"cards": []},
        report=report,
        lineage={"run_id": "test-run", "schema_version": "1.0", "artifact_hashes": {}},
        output_path=dashboard_html
    )
    dash_content = dashboard_html.read_text(encoding="utf-8")
    assert "<script>alert('XSS')</script>" not in dash_content
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in dash_content or "&lt;script&gt;alert('XSS')&lt;/script&gt;" in dash_content


def test_dashboard_escapes_malicious_profile_timestamp_and_sets_csp(tmp_path: Path):
    dashboard_html = tmp_path / "dashboard.html"
    payload = "</script><script>alert(1)</script>"
    generate_dashboard_html(
        raw_scan={"target": "safe.test", "entities": []},
        dossier={"target": "safe.test", "profiled_at": payload, "risk_score": "invalid", "risk_features": []},
        explanation_cards={"cards": []}, report={"audit_gate": {}},
        lineage={"run_id": "run", "artifact_hashes": {}}, output_path=dashboard_html,
    )
    rendered = dashboard_html.read_text(encoding="utf-8")
    assert payload not in rendered
    assert "Content-Security-Policy" in rendered


def test_blocked_report_is_review_only_and_cannot_export_misp(tmp_path: Path, monkeypatch):
    report = {
        "summary": {"target": "blocked.test", "scan_date": "2026-01-01T00:00:00Z"},
        "risk_assessment": {"score_mode": "STUB"},
        "audit_gate": {"status": "FAIL"},
        "findings": [],
    }
    class CapturingHTML:
        def __init__(self, string):
            self.string = string

        def write_pdf(self, path):
            Path(path).write_text(self.string, encoding="utf-8")

    monkeypatch.setitem(sys.modules, "weasyprint", type("FakeWeasyPrint", (), {"HTML": CapturingHTML}))
    html_path = export_pdf(report, tmp_path / "review.pdf")
    assert "NOT CLEARED FOR DISSEMINATION" in html_path.read_text(encoding="utf-8")
    with pytest.raises(ReleaseBlockedError):
        export_misp(report, tmp_path / "blocked-misp.json")


def test_evidence_ids_and_aggregation():
    """Verify entity deduplication aggregates evidence sightings and assigns unique evidence IDs."""
    sf_items = [
        {"type": "DOMAIN_NAME", "data": "provenance.test", "module": "sfp_whois", "source": "Whois"},
        {"type": "DOMAIN_NAME", "data": "provenance.test", "module": "sfp_dnsresolve", "source": "DNS"},
        {"type": "DOMAIN_NAME", "data": "provenance.test", "module": "sfp_ssl", "source": "SSL"},
        {"type": "IP_ADDRESS", "data": "2001:db8::1", "module": "sfp_dnsresolve", "source": "DNS"}, # IPv6
        {"type": "IP_ADDRESS", "data": "999.999.999.999", "module": "sfp_bad", "source": "Bad"} # Invalid IP
    ]
    
    scan = generate_raw_scan("provenance.test", sf_items)
    entities = scan["entities"]
    
    # 1. Deduplication check: provenance.test should appear exactly once
    domain_ents = [e for e in entities if e["value"] == "provenance.test"]
    assert len(domain_ents) == 1
    dom = domain_ents[0]
    
    # 2. Evidence aggregation check
    assert dom["evidence_id"].startswith("ev-")
    assert len(dom["evidence_sources"]) == 3
    assert dom["metadata"]["sightings_count"] == 3
    
    # 3. IPv6 accepted, invalid IP rejected
    ip_vals = [e["value"] for e in entities if e["type"] == "ip"]
    assert "2001:db8::1" in ip_vals
    assert "999.999.999.999" not in ip_vals


def test_pipeline_export_dashboard_and_lineage(tmp_path: Path):
    """Verify that end-to-end pipeline with --export-dashboard generates dashboard HTML and cryptographic lineage."""
    sf_data = [
        {"type": "DOMAIN_NAME", "data": "lineage.test", "module": "sfp_test"},
        {"type": "IP_ADDRESS", "data": "198.51.100.2", "module": "sfp_test"}
    ]
    sf_file = tmp_path / "sf.json"
    sf_file.write_text(json.dumps(sf_data), encoding="utf-8")
    
    results = pipeline_from_existing_scan(
        target="lineage.test",
        spiderfoot_json=str(sf_file),
        output_dir=str(tmp_path),
        do_export_dashboard=True,
        mind_dry_run=True,
        skip_graph=True
    )
    
    assert "xai_dashboard" in results
    assert Path(results["xai_dashboard"]).exists()
    assert "lineage" in results
    lineage_path = Path(results["lineage"])
    assert lineage_path.exists()
    
    lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
    assert "run_id" in lineage
    assert "artifact_hashes" in lineage
    assert "raw_scan.json" in lineage["artifact_hashes"]
    assert "dossier.json" in lineage["artifact_hashes"]
