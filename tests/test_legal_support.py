from legal_support import REQUIRED_NOTICE, generate_electronic_record_certificate


def test_legal_draft_has_disclaimer_and_never_fabricates_missing_facts():
    certificate = generate_electronic_record_certificate(
        {"case_id": "CASE-1", "jurisdiction": "IN"},
        {"evidence_id": "ev-1", "sha256": "sha256:" + "a" * 64},
        jurisdiction="IN",
    )
    assert REQUIRED_NOTICE in certificate
    assert "Case ID: CASE-1" in certificate
    assert "[NOT PROVIDED]" in certificate
    assert "REQUIRES HUMAN COMPLETION" in certificate
