#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

"$PYTHON" "$ROOT/demo.py" \
  --config "$ROOT/config.json" \
  --output "$ROOT/results/latest" \
  "$@"
