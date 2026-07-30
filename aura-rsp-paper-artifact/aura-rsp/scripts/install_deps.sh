#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

if [[ ! -x "$PYTHON" ]]; then
    python3 -m venv "$VENV"
fi
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$ROOT/requirements-aura.lock"
"$PYTHON" -c "import cryptography, py_ecc, requests; print('AURA_DEPENDENCIES_PASS')"
