#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

if [[ ! -x "$VENV/bin/python" ]]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -e "$ROOT[smdpp,aura,experiment]"
"$VENV/bin/python" -m pip freeze >"$ROOT/results/integration-environment.lock"
echo "PYSIM_AURA_DEPENDENCIES_READY=$VENV"
