#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${PYSIM_AURA_VENV:-$HOME/.venvs/pysim-aura-integration}"
PYTHON="${PYSIM_AURA_PYTHON:-$VENV/bin/python}"

# install_deps.sh creates the normal shared venv. Falling back to the system
# interpreter keeps the installer usable in a clean clone without introducing
# a dependency on any older local baseline or standalone prototype.
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3 || true)"
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

RUNTIME="$ROOT/runtime/aura"
LOG_DIR="$ROOT/logs"
RESULT_DIR="$ROOT/results"
mkdir -p "$RUNTIME" "$LOG_DIR" "$RESULT_DIR"
