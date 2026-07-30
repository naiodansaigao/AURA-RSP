#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AURA_ROOT="$(CDPATH= cd -- "$ROOT/../../aura-rsp" && pwd)"
VENV="${AURA_RSP_VENV:-$HOME/.venvs/aura-rsp}"
PYTHON="${PYTHON:-$VENV/bin/python}"

if [[ ! -x "$PYTHON" ]]; then
  echo "找不到AURA Python环境: $PYTHON" >&2
  echo "请先运行: bash \"$AURA_ROOT/scripts/install_deps.sh\"" >&2
  exit 2
fi

export PYTHONPATH="$AURA_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

"$PYTHON" "$ROOT/demo.py" \
  --config "$ROOT/config.json" \
  --output "$ROOT/results/latest" \
  "$@"
