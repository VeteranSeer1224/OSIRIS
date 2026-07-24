"""Immutable local raw-evidence storage with verified reads."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


class EvidenceIntegrityError(ValueError):
    pass


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _require_safe_identifier(value: str, name: str) -> str:
    if not SAFE_IDENTIFIER.fullmatch(value):
        raise EvidenceIntegrityError(f"{name} is not a safe storage identifier")
    return value


@dataclass(frozen=True)
class RawEvidenceRecord:
    evidence_id: str
    content_id: str
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
    observation_path: str


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
        _require_safe_identifier(case_id, "case_id")
        _require_safe_identifier(run_id, "run_id")
        digest = hashlib.sha256(data).hexdigest()
        content_id = f"sha256:{digest}"
        evidence_id = f"obs-{uuid.uuid4()}"
        relative_path = Path("raw-evidence") / "blobs" / "sha256" / digest
        observation_path = (
            Path("raw-evidence") / "observations" / case_id / run_id / f"{evidence_id}.json"
        )
        payload_path = self.root / relative_path
        metadata_path = self.root / observation_path
        self.raw_root.mkdir(parents=True, exist_ok=True)
        record = RawEvidenceRecord(
            evidence_id=evidence_id, content_id=content_id, case_id=case_id, run_id=run_id,
            sha256=f"sha256:{digest}", byte_length=len(data),
            mime_type=mime_type or mimetypes.guess_type(source_identifier)[0] or "application/octet-stream",
            collected_at=datetime.now(timezone.utc).isoformat(), source_type=source_type,
            collector_version=collector_version, source_identifier=source_identifier,
            relative_path=relative_path.as_posix(), observation_path=observation_path.as_posix(),
        )
        payload_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        if payload_path.exists():
            existing = payload_path.read_bytes()
            if hashlib.sha256(existing).hexdigest() != digest or len(existing) != len(data):
                raise EvidenceIntegrityError(f"content-addressed blob is corrupt: {content_id}")
        else:
            with payload_path.open("xb") as handle:
                handle.write(data)
        try:
            with metadata_path.open("x", encoding="utf-8") as handle:
                json.dump(asdict(record), handle, sort_keys=True, indent=2)
        except FileExistsError as exc:
            raise EvidenceIntegrityError("raw evidence write raced with another process") from exc
        return record

    def read_record(self, evidence_id: str) -> RawEvidenceRecord:
        _require_safe_identifier(evidence_id, "evidence_id")
        candidates = list((self.raw_root / "observations").glob(f"*/*/{evidence_id}.json"))
        if not candidates:
            raise EvidenceIntegrityError(f"evidence metadata is missing: {evidence_id}")
        if len(candidates) != 1:
            raise EvidenceIntegrityError(f"evidence metadata is ambiguous: {evidence_id}")
        data = json.loads(candidates[0].read_text(encoding="utf-8"))
        return RawEvidenceRecord(**data)

    def verify(self, record: RawEvidenceRecord) -> None:
        _require_safe_identifier(record.evidence_id, "evidence_id")
        _require_safe_identifier(record.case_id, "case_id")
        _require_safe_identifier(record.run_id, "run_id")
        if not record.sha256.startswith("sha256:") or record.content_id != record.sha256:
            raise EvidenceIntegrityError("evidence digest identifiers are inconsistent")
        digest_hex = record.sha256.removeprefix("sha256:")
        expected_payload = Path("raw-evidence") / "blobs" / "sha256" / digest_hex
        expected_observation = (
            Path("raw-evidence") / "observations" / record.case_id / record.run_id
            / f"{record.evidence_id}.json"
        )
        if Path(record.relative_path) != expected_payload:
            raise EvidenceIntegrityError("evidence payload path is not content-addressed")
        if Path(record.observation_path) != expected_observation:
            raise EvidenceIntegrityError("evidence observation path is inconsistent")
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
        metadata_path = (self.root / record.observation_path).resolve()
        if self.root not in metadata_path.parents:
            raise EvidenceIntegrityError("evidence observation path escapes store root")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceIntegrityError(
                f"evidence observation is unavailable: {record.evidence_id}"
            ) from exc
        if metadata != asdict(record):
            raise EvidenceIntegrityError(
                f"evidence observation metadata mismatch: {record.evidence_id}"
            )
