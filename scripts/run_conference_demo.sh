#!/usr/bin/env bash
# Offline OSIRIS demonstration: fixture replay only; never runs active collection.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
OUT_DIR="${1:-$ROOT/demo-output}"
CASE_ID="DEMO-REVIEW-ONLY"
RUN_ID="offline-fixture-run"

mkdir -p "$OUT_DIR"
"$PYTHON" "$ROOT/run_pipeline.py" \
  --target example.com \
  --input "$ROOT/samples/spiderfoot_small.json" \
  --output-dir "$OUT_DIR" \
  --export-pdf \
  --export-dashboard

# The stub dossier is deliberately blocked from external dissemination. Build
# a signed local-development capsule to demonstrate integrity verification.
KEY="$(mktemp)"
CAPSULE="$OUT_DIR/OSIRIS-Evidence-Capsule"
trap 'rm -f "$KEY"' EXIT
"$PYTHON" "$ROOT/osiris.py" capsule keygen "$KEY"
"$PYTHON" "$ROOT/osiris.py" capsule build --source "$OUT_DIR" --output "$CAPSULE" \
  --case "$CASE_ID" --run "$RUN_ID" --key "$KEY"
"$PYTHON" "$ROOT/osiris.py" verify "$CAPSULE"

echo "Demo completed. Output is review-only; do not disseminate STUB artifacts."
