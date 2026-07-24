#!/usr/bin/env bash
# Offline OSIRIS demonstration: fixture replay only; never runs active collection.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
OUT_ROOT="${1:-$ROOT/demo-output}"
"$PYTHON" "$ROOT/osiris.py" demo conference --output "$OUT_ROOT"
