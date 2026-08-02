import pytest

from spiderfoot_runner import SpiderFootScanError, _wait_for_scan


class FakeProcess:
    exitcode = None

    def is_alive(self):
        return True


class FakeDb:
    def __init__(self, statuses):
        self.statuses = iter(statuses)
        self.updates = []

    def scanInstanceGet(self, _scan_id):
        status = next(self.statuses)
        return [None, None, None, None, None, status]

    def scanInstanceSet(self, scan_id, **values):
        self.updates.append((scan_id, values))


def test_wait_for_scan_returns_only_finished_status():
    seen = []
    status = _wait_for_scan(
        FakeProcess(), FakeDb(["RUNNING", "FINISHED"]), "scan-1",
        timeout_seconds=2, cancel_check=None,
        status_callback=lambda value, scan_id: seen.append((value, scan_id)),
        poll_interval=0.05,
    )
    assert status == "FINISHED"
    assert seen[-1] == ("FINISHED", "scan-1")


@pytest.mark.parametrize("terminal", ["ERROR-FAILED", "ABORTED", "ABORT-REQUESTED"])
def test_wait_for_scan_rejects_non_success_terminal_status(terminal):
    with pytest.raises(SpiderFootScanError) as raised:
        _wait_for_scan(
            FakeProcess(), FakeDb([terminal]), "scan-2",
            timeout_seconds=2, cancel_check=None, status_callback=None,
            poll_interval=0.05,
        )
    assert raised.value.status == terminal


def test_wait_for_scan_cancellation_requests_abort():
    database = FakeDb(["RUNNING"])
    with pytest.raises(SpiderFootScanError) as raised:
        _wait_for_scan(
            FakeProcess(), database, "scan-3", timeout_seconds=2,
            cancel_check=lambda: True, status_callback=None, poll_interval=0.05,
        )
    assert raised.value.status == "CANCELLED"
    assert database.updates == [("scan-3", {"status": "ABORT-REQUESTED"})]
