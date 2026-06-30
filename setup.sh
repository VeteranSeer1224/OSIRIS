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
set -e

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
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo ""
echo "[3/5] Upgrading pip..."
pip install --upgrade pip

# ── 3. Python dependencies (pinned in requirements.txt) ──────────────────
echo ""
echo "[4/5] Installing Python dependencies..."
# Pre-install pinned CPU-only PyTorch (~192MB) so explabox doesn't pull down 6GB of CUDA drivers
pip install torch==2.12.1+cpu --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt

# ── 4. SpiderFoot (Stage 1 — optional, for live scans) ───────────────────
echo ""
echo "[5/5] Setting up SpiderFoot..."
if [ ! -d "spiderfoot" ]; then
    git clone https://github.com/smicallef/spiderfoot.git
fi
pip install -r spiderfoot/requirements.txt

# ── 5. Ollama (Stage 2 — local LLM, optional) ───────────────────────────
echo ""
echo "Installing Ollama for local LLM inference (Stage 2)..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo "To pull a model, run: ollama pull llama3.2"

echo ""
echo "=========================================="
echo "  Setup complete!"
echo ""
echo "  Activate your venv:"
echo "    source venv/bin/activate"
echo ""
echo "  Run the pipeline:"
echo "    python run_pipeline.py --target example.com \\"
echo "      --input samples/spiderfoot_full.json \\"
echo "      --output-dir outputs/ --mind-live"
echo "=========================================="