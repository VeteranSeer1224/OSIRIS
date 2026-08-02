import io
import json
from pathlib import Path

import pytest

import osiris
from terminal_wizard import (
    APPROVAL_PHRASE,
    CaseWorkspace,
    OsirisWizard,
    TerminalIO,
    WizardCancelled,
)


def _metadata(case_id: str = "CASE-WIZARD") -> dict:
    return {
        "case_id": case_id,
        "title": "Wizard test",
        "purpose": "Authorized integration fixture",
        "jurisdiction": "IN",
        "investigator": {"name": "Investigator", "id": "I-1", "organization": "Lab"},
        "targets": ["target.example"],
        "data_retention_policy": "Delete after test",
        "handling_marking": "TLP:CLEAR",
        "additional_sources": [],
    }


def _io(responses: list[str]) -> TerminalIO:
    values = iter(responses)
    return TerminalIO(input_fn=lambda _prompt: next(values), secret_fn=lambda _prompt: "secret", output=io.StringIO())


def test_case_workspace_creates_isolated_case_tree(tmp_path: Path):
    workspace = CaseWorkspace(tmp_path / "cases")
    case_path = workspace.create(_metadata())
    assert json.loads((case_path / "case.json").read_text())["status"] == "OPEN"
    for folder in ("authorization", "capsules", "inputs", "notes", "runs"):
        assert (case_path / folder).is_dir()
    assert workspace.list_cases()[0]["case_id"] == "CASE-WIZARD"
    with pytest.raises(ValueError, match="case ID"):
        workspace.case_path("../escape")


def test_human_approval_copies_hashes_and_verifies_source_document(tmp_path: Path):
    workspace = CaseWorkspace(tmp_path / "cases")
    case_path = workspace.create(_metadata())
    wizard = OsirisWizard(
        workspace=workspace,
        io=_io(["2", "", "", "", ""]),
    )
    wizard.create_authorization(case_path)
    source = tmp_path / "signed-authorization.txt"
    source.write_text("approved scope and signature fixture", encoding="utf-8")
    wizard.io = _io([
        str(source), "Authorized Person", "Security Lead", "A-1",
        APPROVAL_PHRASE, "yes",
    ])
    wizard.approve_authorization(case_path)
    authorization = wizard.verify_authorization_artifacts(
        case_path, active=True, target="target.example"
    )
    assert authorization.status.value == "APPROVED"
    assert authorization.active_scanning_authorized is True
    record = json.loads((case_path / "authorization" / "approval-record.json").read_text())
    copied = case_path / record["source_document"]
    copied.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="hash changed"):
        wizard.verify_authorization_artifacts(case_path, active=True, target="target.example")


def test_approval_requires_exact_human_attestation(tmp_path: Path):
    workspace = CaseWorkspace(tmp_path / "cases")
    case_path = workspace.create(_metadata())
    wizard = OsirisWizard(workspace=workspace, io=_io(["1", "", "", "", ""]))
    wizard.create_authorization(case_path)
    source = tmp_path / "authorization.txt"
    source.write_text("scope", encoding="utf-8")
    wizard.io = _io([str(source), "Approver", "Lead", "A-1", "not approved"])
    with pytest.raises(WizardCancelled):
        wizard.approve_authorization(case_path)
    auth = json.loads((case_path / "authorization" / "authorization.json").read_text())
    assert auth["status"] == "DRAFT"
    assert not (case_path / "authorization" / "approval-record.json").exists()


def test_osiris_without_subcommand_launches_wizard(monkeypatch):
    monkeypatch.setattr(osiris, "run_wizard", lambda **_kwargs: 17)
    assert osiris.main([]) == 17
    assert osiris.main(["wizard", "--cases-root", "/tmp/test-cases"]) == 17


def test_terminal_choice_reprompts_after_invalid_input():
    terminal = _io(["invalid", "9", "2"])
    assert terminal.choose("Pick", [("a", "First"), ("b", "Second")]) == "b"
    assert terminal.output.getvalue().count("Choose one of the numbered options") == 2
