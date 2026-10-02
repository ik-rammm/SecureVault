#!/bin/bash
# SecureVault — Development server
set -e

echo "========================================"
echo "  SecureVault v2 — Starting dev server"
echo "========================================"

cd "$(dirname "$0")"

# Install dependencies
pip install -r requirements.txt -q

# Create data directories
mkdir -p data/vaults models

# Run
python main.py
