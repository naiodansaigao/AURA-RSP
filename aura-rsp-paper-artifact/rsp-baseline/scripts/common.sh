#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYSIM_DIR="$ROOT/third_party/pysim"
LPAC_DIR="$ROOT/third_party/lpac"
VENV="${RSP_BASELINE_VENV:-$HOME/.venvs/rsp-baseline}"
PYTHON="$VENV/bin/python"
PKI_DIR="$PYSIM_DIR/smdpp-data/generated"
RUNTIME_DIR="$ROOT/runtime"
LOG_DIR="$ROOT/logs"

set -a
# shellcheck disable=SC1091
source "$ROOT/config/baseline.env"
set +a

export NO_PROXY="${NO_PROXY:-},$SMDPP_HOST,127.0.0.1,localhost"
export no_proxy="${no_proxy:-},$SMDPP_HOST,127.0.0.1,localhost"

mkdir -p "$RUNTIME_DIR" "$LOG_DIR"

