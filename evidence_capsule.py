"""Deterministic local Evidence Capsule builder and Ed25519 verifier."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class CapsuleVerificationError(ValueError):
    pass


MANIFEST_NAME = "artifact-manifest.json"
SIGNATURE_NAME = "manifest-signature.json"
EXCLUDED_NAMES = frozenset({MANIFEST_NAME, SIGNATURE_NAME})


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_development_key(path: str | Path) -> Path:
    """Generate an Ed25519 local-development signing key with restrictive mode."""
    destination = Path(path)
    key = Ed25519PrivateKey.generate()
    destination.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    destination.chmod(0o600)
    return destination


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise CapsuleVerificationError("local development key is not Ed25519")
    return key


def _manifest_entries(root: Path, *, case_id: str, run_id: str, tool_version: str) -> list[dict[str, Any]]:
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in EXCLUDED_NAMES):
        relative = path.relative_to(root).as_posix()
        entries.append({
            "relative_path": relative,
            "media_type": "application/json" if path.suffix in {".json", ".jsonld"} else "application/octet-stream",
            "byte_length": path.stat().st_size,
            "sha256": f"sha256:{_sha256(path)}",
            "artifact_type": path.suffix.lstrip(".") or "file",
            "case_id": case_id,
            "run_id": run_id,
            "parent_artifacts": [],
            "creation_time": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "producing_tool_version": tool_version,
        })
    return entries


def build_capsule(source_dir: str | Path, capsule_dir: str | Path, *, case_id: str, run_id: str, key_path: str | Path, tool_version: str = "OSIRIS/1.0") -> Path:
    """Copy released artifacts into a capsule and sign its canonical manifest."""
    source, capsule = Path(source_dir).resolve(), Path(capsule_dir).resolve()
    if not source.is_dir():
        raise ValueError("source_dir must be an existing directory")
    if capsule.exists():
        raise FileExistsError("capsule destination must not already exist")
    capsule.mkdir(parents=True)
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        if capsule in path.parents:
            continue
        dest = capsule / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    manifest = {
        "schema_version": "1.0", "case_id": case_id, "run_id": run_id,
        "tool_version": tool_version, "files": _manifest_entries(capsule, case_id=case_id, run_id=run_id, tool_version=tool_version),
    }
    manifest_bytes = _canonical_json(manifest)
    (capsule / MANIFEST_NAME).write_bytes(manifest_bytes)
    key = _load_private_key(key_path)
    signature = key.sign(manifest_bytes)
    public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (capsule / SIGNATURE_NAME).write_bytes(_canonical_json({
        "algorithm": "Ed25519", "mode": "local-development",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }))
    return capsule


def verify_capsule(capsule_dir: str | Path) -> dict[str, Any]:
    capsule = Path(capsule_dir)
    try:
        manifest_bytes = (capsule / MANIFEST_NAME).read_bytes()
        manifest = json.loads(manifest_bytes)
        signature = json.loads((capsule / SIGNATURE_NAME).read_text(encoding="utf-8"))
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(signature["public_key"]))
        public_key.verify(base64.b64decode(signature["signature"]), manifest_bytes)
    except Exception as exc:
        raise CapsuleVerificationError(f"manifest signature verification failed: {exc}") from exc
    expected = {entry["relative_path"]: entry for entry in manifest.get("files", [])}
    actual = {path.relative_to(capsule).as_posix() for path in capsule.rglob("*") if path.is_file() and path.name not in EXCLUDED_NAMES}
    if actual != set(expected):
        raise CapsuleVerificationError("capsule has missing or extra files")
    for relative, entry in expected.items():
        path = capsule / relative
        if path.stat().st_size != entry["byte_length"] or f"sha256:{_sha256(path)}" != entry["sha256"]:
            raise CapsuleVerificationError(f"artifact integrity verification failed: {relative}")
        if entry["case_id"] != manifest["case_id"] or entry["run_id"] != manifest["run_id"]:
            raise CapsuleVerificationError(f"artifact case/run mismatch: {relative}")
    return {"status": "PASS", "case_id": manifest["case_id"], "run_id": manifest["run_id"], "file_count": len(expected)}
