from provenance import build_provenance


def test_provenance_links_all_artifacts_to_raw_evidence():
    result = build_provenance(
        case_id="CASE-1", run_id="RUN-1",
        raw_evidence={"evidence_id": "ev-1", "sha256": "sha256:" + "a" * 64,
                      "relative_path": "raw-evidence/ev-1.json", "collected_at": "2026-01-01T00:00:00Z"},
        artifacts={"raw_scan.json": "b" * 64, "dossier.json": "c" * 64},
    )
    assert result["@context"]["prov"] == "http://www.w3.org/ns/prov#"
    artifacts = [node for node in result["@graph"] if node["id"].startswith("osiris:artifact/")]
    assert len(artifacts) == 2
    assert all(node["prov:wasDerivedFrom"] == "osiris:evidence/ev-1" for node in artifacts)
