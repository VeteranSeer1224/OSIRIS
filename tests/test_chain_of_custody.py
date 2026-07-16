import pytest

from chain_of_custody import CustodyIntegrityError, append_event, verify_chain


def test_custody_chain_detects_historical_modification(tmp_path):
    log = tmp_path / "custody.jsonl"
    first = append_event(log, evidence_or_capsule_id="ev-1", case_id="CASE-1", action="collected", actor_identity="collector", purpose="fixture")
    second = append_event(log, evidence_or_capsule_id="ev-1", case_id="CASE-1", action="verified", actor_identity="reviewer", purpose="integrity check")
    assert verify_chain(log) == [first, second]
    log.write_text(log.read_text(encoding="utf-8").replace('"collected"', '"destroyed"'), encoding="utf-8")
    with pytest.raises(CustodyIntegrityError, match="hash"):
        verify_chain(log)
