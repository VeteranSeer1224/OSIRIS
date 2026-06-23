#!/bin/bash
# OSIRIS Stage 0: Foundation Environment Setup



echo "Installing WeasyPrint system dependencies (Required for Person A)..."
sudo apt update
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0

echo "Setting up Python Virtual Environment..."
python3 -m venv .venv
source venv/bin/activate

echo "Installing OSIRIS-Sense dependencies (Person A)..."
git clone https://github.com/smicallef/spiderfoot.git
pip install -r spiderfoot/requirements.txt

echo "Installing OSIRIS-Mind dependencies (Person B)..."
curl -fsSL https://ollama.com/install.sh | sh

echo "Installing OSIRIS-Web & Conscience dependencies (Person C)..."
pip install networkx pyvis explabox weasyprint

echo "Setup complete! Remember to activate your venv: source venv/bin/activate"