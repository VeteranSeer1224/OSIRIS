import pytest
import json

from evidence_capsule import (
    CapsuleVerificationError, build_capsule, generate_development_key,
    verify_capsule, write_public_key,
)


def _source(path, case_id="CASE-1", run_id="RUN-1"):
    path.mkdir()
    common = {"case_id": case_id, "run_id": run_id}
    (path / "raw_scan.json").write_text(json.dumps(common), encoding="utf-8")
    (path / "dossier.json").write_text(json.dumps(common), encoding="utf-8")
    (path / "explanation_cards.json").write_text(json.dumps(common), encoding="utf-8")
    (path / "lineage.json").write_text(json.dumps(common), encoding="utf-8")
    (path / "report.json").write_text(json.dumps({
        "report_metadata": common, "release_decision": {"status": "BLOCKED"},
    }), encoding="utf-8")
    return path


def test_signed_capsule_detects_tampering_and_extra_files(tmp_path):
    source = tmp_path / "source"
    _source(source)
    (source / "provenance.jsonld").write_text('{"@graph": []}', encoding="utf-8")
    key = generate_development_key(tmp_path / "local-dev.pem")
    public_key = write_public_key(key, tmp_path / "trusted.pem")
    capsule = build_capsule(source, tmp_path / "capsule", key_path=key)
    assert verify_capsule(capsule, trusted_public_key=public_key)["status"] == "PASS"
    (capsule / "report.json").write_text('{"report": "tampered"}', encoding="utf-8")
    with pytest.raises(CapsuleVerificationError, match="artifact integrity"):
        verify_capsule(capsule, trusted_public_key=public_key)
    clean_capsule = build_capsule(source, tmp_path / "clean-capsule", key_path=key)
    (clean_capsule / "unexpected.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(CapsuleVerificationError, match="missing or extra"):
        verify_capsule(clean_capsule, trusted_public_key=public_key)


def test_capsule_rejects_inconsistent_ids_and_untrusted_resigning(tmp_path):
    source = _source(tmp_path / "source")
    (source / "dossier.json").write_text(
        json.dumps({"case_id": "OTHER", "run_id": "RUN-1"}), encoding="utf-8"
    )
    trusted_key = generate_development_key(tmp_path / "trusted-private.pem")
    with pytest.raises(CapsuleVerificationError, match="inconsistent"):
        build_capsule(source, tmp_path / "bad", key_path=trusted_key)

    (source / "dossier.json").write_text(
        json.dumps({"case_id": "CASE-1", "run_id": "RUN-1"}), encoding="utf-8"
    )
    attacker_key = generate_development_key(tmp_path / "attacker-private.pem")
    capsule = build_capsule(source, tmp_path / "attacker-capsule", key_path=attacker_key)
    trusted_public = write_public_key(trusted_key, tmp_path / "trusted-public.pem")
    with pytest.raises(CapsuleVerificationError, match="not the trusted key"):
        verify_capsule(capsule, trusted_public_key=trusted_public)


def test_capsule_rejects_private_key_source(tmp_path):
    source = _source(tmp_path / "source")
    key = generate_development_key(source / "signing.pem")
    with pytest.raises(CapsuleVerificationError, match="private key"):
        build_capsule(source, tmp_path / "capsule", key_path=key)


def test_capsule_rejects_symlink_source(tmp_path):
    source = _source(tmp_path / "source")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    (source / "linked.txt").symlink_to(tmp_path / "outside.txt")
    key = generate_development_key(tmp_path / "signing.pem")
    with pytest.raises(CapsuleVerificationError, match="symlink"):
        build_capsule(source, tmp_path / "capsule", key_path=key)


def test_capsule_rejects_secret_source_and_post_build_symlink(tmp_path):
    source = _source(tmp_path / "source")
    (source / ".env").write_text("TOKEN=not-real", encoding="utf-8")
    key = generate_development_key(tmp_path / "signing.pem")
    with pytest.raises(CapsuleVerificationError, match="secret"):
        build_capsule(source, tmp_path / "secret-capsule", key_path=key)

    (source / ".env").unlink()
    public_key = write_public_key(key, tmp_path / "trusted.pem")
    capsule = build_capsule(source, tmp_path / "capsule", key_path=key)
    report = capsule / "report.json"
    original = tmp_path / "original-report.json"
    original.write_bytes(report.read_bytes())
    report.unlink()
    report.symlink_to(original)
    with pytest.raises(CapsuleVerificationError, match="symlink"):
        verify_capsule(capsule, trusted_public_key=public_key)
