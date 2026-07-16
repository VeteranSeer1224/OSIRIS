import json
from pathlib import Path

from osiris import main


def test_cli_builds_and_verifies_capsule(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report.json").write_text("{}", encoding="utf-8")
    key = tmp_path / "dev.pem"
    assert main(["--json", "capsule", "keygen", str(key)]) == 0
    assert main(["--json", "capsule", "build", "--source", str(source), "--output", str(tmp_path / "capsule"), "--case", "CASE-1", "--run", "RUN-1", "--key", str(key)]) == 0
    assert main(["--json", "verify", str(tmp_path / "capsule")]) == 0
    outputs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert all(item["status"] == "PASS" for item in outputs)


def test_cli_returns_nonzero_for_tampered_capsule(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report.json").write_text("{}", encoding="utf-8")
    key = tmp_path / "dev.pem"
    assert main(["capsule", "keygen", str(key)]) == 0
    capsule = tmp_path / "capsule"
    assert main(["capsule", "build", "--source", str(source), "--output", str(capsule), "--case", "CASE-1", "--run", "RUN-1", "--key", str(key)]) == 0
    (capsule / "report.json").write_text("tampered", encoding="utf-8")
    assert main(["verify", str(capsule)]) == 2
