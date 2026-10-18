#!/usr/bin/env bash
set -e

echo "=== 1. Starting FalkorDB Database ==="
docker compose up -d

echo "=== 2. Setting up Python 3.11 virtual environment ==="
python3.11 -m venv .venv || python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "=== 3. Setting up Solidity Compiler 0.8.19 ==="
solc-select install 0.8.19
solc-select use 0.8.19

echo "=== 4. Setting up Environment File ==="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Add your LLM_API_KEY if testing agent mode."
fi

echo "=== 5. Running Ground-Truth Adversarial Red-Team/Blue-Team Harness (Round 0) ==="
python -m src.evaluate --round 0 --mode offline --patch oracle

echo "=== 6. Launching Audit-Chain Dashboard ==="
echo "Streamlit UI will open at: http://localhost:8501"
echo "FalkorDB Browser is available at: http://localhost:3000"
streamlit run app.py
