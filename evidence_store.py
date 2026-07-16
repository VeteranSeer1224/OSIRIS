"""Immutable local raw-evidence storage with verified reads."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


class EvidenceIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class RawEvidenceRecord:
    evidence_id: str
    case_id: str
    run_id: str
    sha256: str
    byte_length: int
    mime_type: str
    collected_at: str
    source_type: str
    collector_version: str
    source_identifier: str
    relative_path: str


class LocalEvidenceStore:
    """Append-only filesystem store used by the offline/demo profile."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.raw_root = self.root / "raw-evidence"

    def preserve(
        self, data: bytes, *, case_id: str, run_id: str, source_type: str,
        source_identifier: str, collector_version: str = "OSIRIS-Sense/1.0",
        mime_type: str | None = None,
    ) -> RawEvidenceRecord:
        digest = hashlib.sha256(data).hexdigest()
        evidence_id = f"ev-{digest[:24]}"
        suffix = Path(source_identifier).suffix or ".bin"
        relative_path = Path("raw-evidence") / f"{evidence_id}{suffix.lower()}"
        payload_path = self.root / relative_path
        metadata_path = payload_path.with_suffix(payload_path.suffix + ".metadata.json")
        self.raw_root.mkdir(parents=True, exist_ok=True)
        record = RawEvidenceRecord(
            evidence_id=evidence_id, case_id=case_id, run_id=run_id,
            sha256=f"sha256:{digest}", byte_length=len(data),
            mime_type=mime_type or mimetypes.guess_type(source_identifier)[0] or "application/octet-stream",
            collected_at=datetime.now(timezone.utc).isoformat(), source_type=source_type,
            collector_version=collector_version, source_identifier=source_identifier,
            relative_path=relative_path.as_posix(),
        )
        if payload_path.exists() or metadata_path.exists():
            existing = self.read_record(evidence_id, suffix)
            if existing.sha256 != record.sha256 or existing.byte_length != record.byte_length:
                raise EvidenceIntegrityError(f"immutable evidence ID collision: {evidence_id}")
            return existing
        try:
            with payload_path.open("xb") as handle:
                handle.write(data)
            with metadata_path.open("x", encoding="utf-8") as handle:
                json.dump(asdict(record), handle, sort_keys=True, indent=2)
        except FileExistsError as exc:
            raise EvidenceIntegrityError("raw evidence write raced with another process") from exc
        return record

    def read_record(self, evidence_id: str, suffix: str = ".bin") -> RawEvidenceRecord:
        candidates = list(self.raw_root.glob(f"{evidence_id}.*.metadata.json"))
        if not candidates:
            raise EvidenceIntegrityError(f"evidence metadata is missing: {evidence_id}")
        data = json.loads(candidates[0].read_text(encoding="utf-8"))
        return RawEvidenceRecord(**data)

    def verify(self, record: RawEvidenceRecord) -> None:
        path = (self.root / record.relative_path).resolve()
        if self.root not in path.parents:
            raise EvidenceIntegrityError("evidence path escapes store root")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise EvidenceIntegrityError(f"evidence payload is unavailable: {record.evidence_id}") from exc
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if digest != record.sha256 or len(data) != record.byte_length:
            raise EvidenceIntegrityError(f"evidence integrity verification failed: {record.evidence_id}")
