#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PYTHON="${AURA_RSP_VENV:-$HOME/.venvs/aura-rsp}/bin/python"
PYTHON="${PYTHON:-$DEFAULT_PYTHON}"

if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" || ! -x "$PYTHON" ]]; then
  echo "找不到Python 3环境" >&2
  exit 2
fi

"$PYTHON" "$ROOT/demo.py" \
  --config "$ROOT/config.json" \
  --output "$ROOT/results/latest" \
  "$@"

