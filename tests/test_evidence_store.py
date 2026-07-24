import pytest
from dataclasses import replace

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


def test_same_bytes_create_distinct_per_run_observations(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    first = store.preserve(
        b"same", case_id="CASE-1", run_id="RUN-1",
        source_type="fixture", source_identifier="fixture.json",
    )
    second = store.preserve(
        b"same", case_id="CASE-2", run_id="RUN-2",
        source_type="fixture", source_identifier="fixture.json",
    )
    assert first.relative_path == second.relative_path
    assert first.evidence_id != second.evidence_id
    assert first.observation_path != second.observation_path
    assert first.observation_path.startswith("raw-evidence/observations/CASE-1/RUN-1/")
    assert second.observation_path.startswith("raw-evidence/observations/CASE-2/RUN-2/")
    assert second.case_id == "CASE-2"
    assert second.run_id == "RUN-2"


def test_evidence_rejects_unsafe_ids_and_forged_observation_metadata(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    with pytest.raises(EvidenceIntegrityError, match="safe storage"):
        store.preserve(
            b"escape", case_id="../OTHER", run_id="RUN-1",
            source_type="fixture", source_identifier="fixture.json",
        )

    record = store.preserve(
        b"original", case_id="CASE-1", run_id="RUN-1",
        source_type="fixture", source_identifier="fixture.json",
    )
    forged = replace(record, case_id="CASE-2")
    with pytest.raises(EvidenceIntegrityError, match="observation path"):
        store.verify(forged)
