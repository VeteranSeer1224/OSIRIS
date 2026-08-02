"""Atomic artifact I/O and isolated-run directory enforcement."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class ArtifactIOError(ValueError):
    """Raised when artifact isolation or atomic persistence fails."""


def require_empty_directory(path: str | Path) -> Path:
    """Create an output directory, refusing any pre-existing content."""
    destination = Path(path).resolve()
    if destination.exists():
        if not destination.is_dir():
            raise ArtifactIOError(f"run output path is not a directory: {destination}")
        existing = sorted(item.name for item in destination.iterdir())
        if existing:
            preview = ", ".join(existing[:5])
            raise ArtifactIOError(
                f"run output directory is not empty ({preview}); create a new isolated run"
            )
    else:
        destination.mkdir(parents=True, exist_ok=False)
    return destination


def atomic_write_bytes(path: str | Path, payload: bytes, *, mode: int | None = None) -> Path:
    """Atomically replace one artifact in its destination directory."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def atomic_write_text(
    path: str | Path, payload: str, *, encoding: str = "utf-8", mode: int | None = None
) -> Path:
    return atomic_write_bytes(path, payload.encode(encoding), mode=mode)


def atomic_write_json(path: str | Path, value: Any) -> Path:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    return atomic_write_text(path, payload + "\n")
