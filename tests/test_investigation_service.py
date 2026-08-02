import io
import json
from pathlib import Path

from investigation_service import InvestigationService, RunRequest
from terminal_wizard import CaseWorkspace, OsirisWizard, TerminalIO


def _case_metadata():
    return {
        "case_id": "CASE-E2E", "title": "Offline wizard E2E",
        "purpose": "Authorized fixture replay", "jurisdiction": "IN",
        "investigator": {"name": "Test Investigator", "id": "INV-1", "organization": "Test Lab"},
        "targets": ["example.com"], "data_retention_policy": "Delete after test",
        "handling_marking": "TLP:CLEAR", "additional_sources": [],
    }


def test_offline_wizard_run_uses_shared_service_and_saves_complete_case_artifacts(tmp_path: Path):
    workspace = CaseWorkspace(tmp_path / "cases")
    service = InvestigationService(workspace)
    created = service.create_case(_case_metadata())
    case_path = Path(created["path"])
    source = tmp_path / "fixture.json"
    source.write_text(json.dumps([
        {"type": "DOMAIN_NAME", "data": "example.com", "module": "sfp_test"},
        {"type": "IP_ADDRESS", "data": "93.184.216.34", "module": "sfp_test"},
    ]), encoding="utf-8")

    responses = iter([
        "2", str(source),       # replay + source
        "n",                    # no additional source
        "3",                    # dry LLM
        "n", "n", "n",       # PDF, dashboard, graph
        "yes",                  # final human run confirmation
        "",                     # pause
    ])
    output = io.StringIO()
    wizard = OsirisWizard(
        workspace=workspace,
        io=TerminalIO(input_fn=lambda _prompt: next(responses), output=output),
    )
    wizard.run_investigation(case_path)

    runs = service.list_runs("CASE-E2E")
    assert len(runs) == 1
    assert runs[0]["status"] == "COMPLETED"
    assert runs[0]["summary"]["output_class"] == "REVIEW_ONLY"
    run_dir = case_path / "runs" / runs[0]["run_name"]
    assert not (run_dir / "run.json").exists()
    for name in (
        "raw_scan.json", "dossier.json", "explanation_cards.json", "report.json",
        "collection-status.json", "chain-of-custody.jsonl", "legal_draft.txt",
        "provenance.jsonld", "lineage.json", "run-summary.json",
        "release-decision.json",
    ):
        assert (run_dir / name).is_file(), name
    raw_scan = json.loads((run_dir / "raw_scan.json").read_text(encoding="utf-8"))
    assert raw_scan["case_id"] == "CASE-E2E"
    assert "Technical=PASS" in output.getvalue()


def test_case_service_rejects_unsupported_target_and_excessive_modules(tmp_path: Path):
    service = InvestigationService(CaseWorkspace(tmp_path / "cases"))
    invalid = _case_metadata()
    invalid["targets"] = ["not a target"]
    try:
        service.create_case(invalid)
    except ValueError as exc:
        assert "domain or IP" in str(exc)
    else:
        raise AssertionError("invalid target was accepted")
    try:
        RunRequest(
            target="example.com", collection="replay", source_input="fixture.json",
            modules="not_a_spiderfoot_module",
        ).validate()
    except ValueError as exc:
        assert "sfp_" in str(exc)
    else:
        raise AssertionError("invalid module name was accepted")
