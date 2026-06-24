#!/bin/bash
# OSIRIS Stage 0: Foundation Environment Setup

# Exit immediately if a command exits with a non-zero status
set -e

echo "Installing system dependencies (WeasyPrint, zstd, and Python tooling)..."
sudo apt update
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 zstd python3-pip python3-venv

echo "Setting up Python Virtual Environment..."
# Creating the venv in .venv
python3 -m venv .venv

# FIX: Activating from .venv/bin/activate (added the missing dot)
source .venv/bin/activate

echo "Upgrading pip inside the virtual environment..."
pip install --upgrade pip

echo "Installing OSIRIS-Sense dependencies (Person A)..."
# Avoid crashing if the directory already exists
if [ ! -d "spiderfoot" ]; then
    git clone https://github.com/smicallef/spiderfoot.git
fi
pip install -r spiderfoot/requirements.txt

echo "Installing OSIRIS-Mind dependencies (Person B)..."
curl -fsSL https://ollama.com/install.sh | sh

echo "Installing OSIRIS-Web & Conscience dependencies (Person C)..."
pip install networkx pyvis explabox weasyprint

echo "--------------------------------------------------------"
echo "Setup complete!"
echo "To start working, remember to activate your venv using:"
echo "source .venv/bin/activate"
echo "--------------------------------------------------------"