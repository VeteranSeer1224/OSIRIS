import json
from pathlib import Path

from osiris import main


def _source(path):
    path.mkdir()
    common = {"case_id": "CASE-1", "run_id": "RUN-1"}
    for name in ("raw_scan.json", "dossier.json", "explanation_cards.json", "lineage.json"):
        (path / name).write_text(json.dumps(common), encoding="utf-8")
    (path / "report.json").write_text(json.dumps({
        "report_metadata": common, "release_decision": {"status": "BLOCKED"},
    }), encoding="utf-8")


def test_cli_builds_and_verifies_capsule(tmp_path, capsys):
    source = tmp_path / "source"
    _source(source)
    key = tmp_path / "dev.pem"
    public_key = tmp_path / "dev-public.pem"
    assert main(["--json", "capsule", "keygen", str(key), "--public-key", str(public_key)]) == 0
    assert main(["--json", "capsule", "build", "--source", str(source), "--output", str(tmp_path / "capsule"), "--key", str(key)]) == 0
    assert main(["--json", "verify", str(tmp_path / "capsule"), "--trusted-key", str(public_key)]) == 0
    outputs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert all(item["status"] == "PASS" for item in outputs)


def test_cli_returns_nonzero_for_tampered_capsule(tmp_path):
    source = tmp_path / "source"
    _source(source)
    key = tmp_path / "dev.pem"
    public_key = tmp_path / "dev-public.pem"
    assert main(["capsule", "keygen", str(key), "--public-key", str(public_key)]) == 0
    capsule = tmp_path / "capsule"
    assert main(["capsule", "build", "--source", str(source), "--output", str(capsule), "--key", str(key)]) == 0
    (capsule / "report.json").write_text("tampered", encoding="utf-8")
    assert main(["verify", str(capsule), "--trusted-key", str(public_key)]) == 2


def test_noninteractive_case_commands_share_workspace_service(tmp_path, capsys):
    root = tmp_path / "cases"
    args = [
        "--cases-root", str(root), "case", "create",
        "--case-id", "CASE-CLI", "--title", "CLI case",
        "--purpose", "Offline fixture", "--investigator-name", "Investigator",
        "--investigator-id", "I-1", "--organization", "Lab",
        "--target", "example.com", "--json",
    ]
    assert main(args) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["case_id"] == "CASE-CLI"
    assert main(["--cases-root", str(root), "case", "list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["cases"][0]["case_id"] == "CASE-CLI"
