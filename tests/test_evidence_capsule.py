import pytest

from evidence_capsule import CapsuleVerificationError, build_capsule, generate_development_key, verify_capsule


def test_signed_capsule_detects_tampering_and_extra_files(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report.json").write_text('{"report": "review"}', encoding="utf-8")
    (source / "provenance.jsonld").write_text('{"@graph": []}', encoding="utf-8")
    key = generate_development_key(tmp_path / "local-dev.pem")
    capsule = build_capsule(source, tmp_path / "capsule", case_id="CASE-1", run_id="RUN-1", key_path=key)
    assert verify_capsule(capsule)["status"] == "PASS"
    (capsule / "report.json").write_text('{"report": "tampered"}', encoding="utf-8")
    with pytest.raises(CapsuleVerificationError, match="artifact integrity"):
        verify_capsule(capsule)
    clean_capsule = build_capsule(source, tmp_path / "clean-capsule", case_id="CASE-1", run_id="RUN-1", key_path=key)
    (clean_capsule / "unexpected.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(CapsuleVerificationError, match="missing or extra"):
        verify_capsule(clean_capsule)
