"""Deterministic local Evidence Capsule builder and Ed25519 verifier."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from artifact_io import atomic_write_bytes


class CapsuleVerificationError(ValueError):
    pass


MANIFEST_NAME = "artifact-manifest.json"
SIGNATURE_NAME = "manifest-signature.json"
EXCLUDED_NAMES = frozenset({MANIFEST_NAME, SIGNATURE_NAME})
IDENTITY_ARTIFACTS = (
    "raw_scan.json", "dossier.json", "explanation_cards.json",
    "report.json", "lineage.json",
)
FORBIDDEN_SOURCE_NAMES = frozenset({".env", "id_rsa", "id_ed25519"})
ALLOWED_ROOT_ARTIFACTS = frozenset({
    "raw_scan.json", "dossier.json", "explanation_cards.json",
    "fairness_report.md", "fairness_report.json",
    "robustness_report.md", "robustness_report.json",
    "report.json", "report.pdf", "graph.html", "xai_dashboard.html",
    "misp_export.json", "stix_export.json", "lineage.json",
    "provenance.jsonld", "chain-of-custody.jsonl", "legal_draft.json", "legal_draft.txt",
    "run-summary.json", "release-decision.json",
    "collection-status.json",
})
ALLOWED_PREFIXES = ("raw-evidence/blobs/sha256/", "raw-evidence/observations/")


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


def write_public_key(private_key_path: str | Path, public_key_path: str | Path) -> Path:
    key = _load_private_key(private_key_path)
    destination = Path(public_key_path)
    destination.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
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
            "parent_artifacts": _parents_for(relative),
            "creation_time": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "producing_tool_version": tool_version,
        })
    return entries


def _parents_for(relative: str) -> list[str]:
    name = Path(relative).name
    if name == "raw_scan.json":
        return []
    if name == "dossier.json":
        return ["raw_scan.json"]
    if name in {"explanation_cards.json", "fairness_report.json", "robustness_report.json"}:
        return ["dossier.json"]
    if name == "report.json":
        return ["raw_scan.json", "dossier.json", "explanation_cards.json"]
    if name in {"lineage.json", "provenance.jsonld"}:
        return ["raw_scan.json"]
    return []


def _artifact_identity(path: Path) -> tuple[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    case_id = data.get("case_id")
    run_id = data.get("run_id")
    if path.name == "report.json":
        metadata = data.get("report_metadata", {})
        case_id, run_id = metadata.get("case_id"), metadata.get("run_id")
    if not isinstance(case_id, str) or not case_id or not isinstance(run_id, str) or not run_id:
        raise CapsuleVerificationError(f"artifact lacks case/run identity: {path.name}")
    return case_id, run_id


def _derive_context(source: Path) -> tuple[str, str, str]:
    identities = []
    for name in IDENTITY_ARTIFACTS:
        path = source / name
        if not path.is_file():
            raise CapsuleVerificationError(f"required identity artifact is missing: {name}")
        identities.append(_artifact_identity(path))
    if len(set(identities)) != 1:
        raise CapsuleVerificationError("source artifacts have inconsistent case/run IDs")
    report = json.loads((source / "report.json").read_text(encoding="utf-8"))
    release = report.get("release_decision")
    if not isinstance(release, dict) or release.get("status") not in {"PASS", "BLOCKED"}:
        raise CapsuleVerificationError("report has no validated release status")
    return identities[0][0], identities[0][1], release["status"]


def _validate_source_files(source: Path, key_path: Path) -> None:
    resolved_key = key_path.resolve()
    for path in source.rglob("*"):
        if path.is_symlink():
            raise CapsuleVerificationError(f"capsule source contains a symlink: {path}")
        if not path.is_file():
            continue
        if path.resolve() == resolved_key:
            raise CapsuleVerificationError("capsule source contains the signing private key")
        lowered = path.name.lower()
        if lowered in FORBIDDEN_SOURCE_NAMES or "secret" in lowered or lowered.endswith((".pem", ".key")):
            raise CapsuleVerificationError(f"capsule source contains an unvalidated secret file: {path.name}")
        if b"PRIVATE KEY" in path.read_bytes()[:4096]:
            raise CapsuleVerificationError(f"capsule source contains private-key material: {path.name}")
        relative = path.relative_to(source).as_posix()
        if relative not in ALLOWED_ROOT_ARTIFACTS and not relative.startswith(ALLOWED_PREFIXES):
            raise CapsuleVerificationError(
                f"capsule source contains a non-allowlisted artifact: {relative}"
            )


def build_capsule(
    source_dir: str | Path,
    capsule_dir: str | Path,
    *,
    key_path: str | Path,
    tool_version: str = "OSIRIS/1.0",
) -> Path:
    """Copy released artifacts into a capsule and sign its canonical manifest."""
    source, capsule = Path(source_dir).resolve(), Path(capsule_dir).resolve()
    if not source.is_dir():
        raise ValueError("source_dir must be an existing directory")
    if capsule.exists():
        raise FileExistsError("capsule destination must not already exist")
    _validate_source_files(source, Path(key_path))
    case_id, run_id, release_status = _derive_context(source)
    capsule.parent.mkdir(parents=True, exist_ok=True)
    staging = capsule.with_name(f".{capsule.name}.in-progress-{uuid.uuid4().hex}")
    staging.mkdir()
    try:
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            if staging in path.parents:
                continue
            dest = staging / path.relative_to(source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
        manifest = {
            "schema_version": "1.0", "case_id": case_id, "run_id": run_id,
            "release_status": release_status, "tool_version": tool_version,
            "files": _manifest_entries(
                staging, case_id=case_id, run_id=run_id, tool_version=tool_version
            ),
        }
        manifest_bytes = _canonical_json(manifest)
        atomic_write_bytes(staging / MANIFEST_NAME, manifest_bytes)
        key = _load_private_key(key_path)
        signature = key.sign(manifest_bytes)
        public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        atomic_write_bytes(staging / SIGNATURE_NAME, _canonical_json({
            "algorithm": "Ed25519", "mode": "local-development",
            "signer_fingerprint": f"sha256:{hashlib.sha256(public_key).hexdigest()}",
            "signature": base64.b64encode(signature).decode("ascii"),
        }))
        os.replace(staging, capsule)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return capsule


def verify_capsule(capsule_dir: str | Path, *, trusted_public_key: str | Path) -> dict[str, Any]:
    capsule = Path(capsule_dir)
    if not capsule.is_dir():
        raise CapsuleVerificationError("capsule must be an existing directory")
    for path in capsule.rglob("*"):
        if path.is_symlink():
            raise CapsuleVerificationError(f"capsule contains a symlink: {path}")
    try:
        manifest_bytes = (capsule / MANIFEST_NAME).read_bytes()
        manifest = json.loads(manifest_bytes)
        signature = json.loads((capsule / SIGNATURE_NAME).read_text(encoding="utf-8"))
        loaded = serialization.load_pem_public_key(Path(trusted_public_key).read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            raise CapsuleVerificationError("trusted key is not Ed25519")
        public_key = loaded
        raw_public_key = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        fingerprint = f"sha256:{hashlib.sha256(raw_public_key).hexdigest()}"
        if signature.get("signer_fingerprint") != fingerprint:
            raise CapsuleVerificationError("capsule signer is not the trusted key")
        public_key.verify(
            base64.b64decode(signature["signature"], validate=True),
            manifest_bytes,
        )
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
    derived_case, derived_run, derived_release = _derive_context(capsule)
    if (
        derived_case != manifest["case_id"]
        or derived_run != manifest["run_id"]
        or derived_release != manifest["release_status"]
    ):
        raise CapsuleVerificationError("capsule artifact context does not match its manifest")
    return {
        "status": "PASS", "case_id": manifest["case_id"],
        "run_id": manifest["run_id"], "release_status": manifest["release_status"],
        "file_count": len(expected),
    }
