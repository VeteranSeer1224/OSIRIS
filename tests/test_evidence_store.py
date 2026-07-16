import pytest

from evidence_store import EvidenceIntegrityError, LocalEvidenceStore


def test_raw_evidence_is_immutable_and_tampering_is_detected(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    record = store.preserve(
        b'{"fixture": true}', case_id="CASE-1", run_id="RUN-1",
        source_type="fixture", source_identifier="fixture.json", mime_type="application/json",
    )
    store.verify(record)
    path = tmp_path / record.relative_path
    with pytest.raises(FileExistsError):
        path.open("xb")
    path.write_bytes(b"tampered")
    with pytest.raises(EvidenceIntegrityError, match="verification failed"):
        store.verify(record)
