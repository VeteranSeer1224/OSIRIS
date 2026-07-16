import pytest

from exports import export_stix21
from release_policy import ReleaseBlockedError


def test_stix_export_is_release_gated(tmp_path):
    blocked = {"risk_assessment": {"score_mode": "STUB"}, "audit_gate": {"status": "FAIL"}}
    with pytest.raises(ReleaseBlockedError, match="STIX export"):
        export_stix21(blocked, tmp_path / "blocked.json")
