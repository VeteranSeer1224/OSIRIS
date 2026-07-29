#!/bin/bash
# OSIRIS Stage 0: Foundation Environment Setup
#
# This script installs all system and Python dependencies needed to run
# the full OSIRIS pipeline from a fresh clone.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh

# Exit immediately if a command exits with a non-zero status
set -euo pipefail

# Reviewed SpiderFoot revision. Update only with collector contract tests and
# a dependency/security review.
SPIDERFOOT_REPOSITORY="https://github.com/smicallef/spiderfoot.git"
SPIDERFOOT_COMMIT="0f815a203afebf05c98b605dba5cf0475a0ee5fd"

echo "=========================================="
echo "  OSIRIS — Environment Setup"
echo "=========================================="

# ── 1. System dependencies (WeasyPrint, zstd, Python tooling) ────────────
echo ""
echo "[1/5] Installing system dependencies..."
sudo apt update
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 zstd python3-pip python3-venv

# ── 2. Python virtual environment ────────────────────────────────────────
echo ""
echo "[2/5] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

echo ""
echo "[3/5] Upgrading pip..."
python -m pip install --upgrade pip

# ── 3. Python dependencies (pinned in requirements.txt) ──────────────────
echo ""
echo "[4/5] Installing Python dependencies..."
python -m pip install -r requirements.txt
python -m pip install -e ".[dev,report,graph,ai,spiderfoot]"

# ── 4. SpiderFoot (Stage 1 — optional, for live scans) ───────────────────
echo ""
echo "[5/5] Setting up SpiderFoot..."
if [ ! -d "spiderfoot" ]; then
    git clone "$SPIDERFOOT_REPOSITORY" spiderfoot
fi
git -C spiderfoot fetch origin "$SPIDERFOOT_COMMIT"
git -C spiderfoot checkout --detach "$SPIDERFOOT_COMMIT"
python -m pip install -r spiderfoot/requirements.txt
python -c "import spiderfoot_runner; spiderfoot_runner.require_spiderfoot_runtime(); print('SpiderFoot runtime verified')"

# ── 5. Ollama (Stage 2 — local LLM, optional) ───────────────────────────
echo ""
echo "Checking optional Ollama local inference runtime..."
if command -v ollama &> /dev/null; then
    echo "Ollama detected. Model installation remains an explicit operator action."
else
    echo "Ollama not installed. Use OpenRouter in the wizard, or install Ollama"
    echo "from a verified package following your organization's software policy."
fi

echo ""
echo "=========================================="
echo "  Setup complete!"
echo ""
echo "  Activate your venv:"
echo "    source .venv/bin/activate"
echo ""
echo "  Start the terminal wizard:"
echo "    osiris"
echo "=========================================="
