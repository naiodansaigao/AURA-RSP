#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${AURA_RSP_VENV:-$HOME/.venvs/aura-rsp}"
PYTHON="$VENV/bin/python"
RUNTIME_DIR="$ROOT/runtime"
LOG_DIR="$ROOT/logs"
export PYTHONPATH="$ROOT/src"
export NO_PROXY="${NO_PROXY:-},127.0.0.1,localhost"
export no_proxy="${no_proxy:-},127.0.0.1,localhost"
mkdir -p "$RUNTIME_DIR" "$LOG_DIR"
