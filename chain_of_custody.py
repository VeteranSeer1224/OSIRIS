"""Append-only, hash-linked chain-of-custody records."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CustodyIntegrityError(ValueError):
    pass


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _event_hash(event: dict[str, Any]) -> str:
    unsigned = dict(event)
    unsigned.pop("current_event_hash", None)
    return f"sha256:{hashlib.sha256(_canonical(unsigned)).hexdigest()}"


def read_events(path: str | Path) -> list[dict[str, Any]]:
    log = Path(path)
    if not log.exists():
        return []
    try:
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    except json.JSONDecodeError as exc:
        raise CustodyIntegrityError(f"invalid custody log: {exc}") from exc


def verify_chain(path: str | Path) -> list[dict[str, Any]]:
    events = read_events(path)
    previous = None
    for event in events:
        required = {"event_id", "evidence_or_capsule_id", "case_id", "action", "timestamp", "actor_identity", "previous_event_hash", "current_event_hash"}
        if missing := required - set(event):
            raise CustodyIntegrityError(f"custody event missing fields: {sorted(missing)}")
        if event["previous_event_hash"] != previous:
            raise CustodyIntegrityError("custody hash chain is broken")
        if event["current_event_hash"] != _event_hash(event):
            raise CustodyIntegrityError("custody event hash is invalid")
        previous = event["current_event_hash"]
    return events


def append_event(
    path: str | Path, *, evidence_or_capsule_id: str, case_id: str, action: str,
    actor_identity: str, purpose: str, previous_custodian: str | None = None,
    new_custodian: str | None = None, location_or_system: str | None = None,
    signature: str | None = None,
) -> dict[str, Any]:
    """Append a record only after verifying the entire preceding chain."""
    log = Path(path)
    events = verify_chain(log)
    event = {
        "event_id": str(uuid.uuid4()), "evidence_or_capsule_id": evidence_or_capsule_id,
        "case_id": case_id, "action": action, "previous_custodian": previous_custodian,
        "new_custodian": new_custodian, "timestamp": datetime.now(timezone.utc).isoformat(),
        "location_or_system": location_or_system, "purpose": purpose,
        "actor_identity": actor_identity, "signature": signature,
        "previous_event_hash": events[-1]["current_event_hash"] if events else None,
    }
    event["current_event_hash"] = _event_hash(event)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return event
