#!/usr/bin/env bash
set -euo pipefail

EXPERIMENT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(CDPATH= cd -- "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"
source "$INTEGRATION_ROOT/integration-scripts/common.sh"
PYTHON="${PYTHON:-$AURA_PYTHON}"

if [[ ! -x "$PYTHON" ]]; then
  echo "AURA Python not found: $PYTHON" >&2
  echo "Run: bash '$INTEGRATION_ROOT/integration-scripts/install_deps.sh'" >&2
  exit 2
fi

export PYTHONPATH="$INTEGRATION_ROOT${PYTHONPATH:+:$PYTHONPATH}"
"$PYTHON" "$EXPERIMENT_ROOT/demo.py" \
  --config "$EXPERIMENT_ROOT/config.json" \
  --output "$EXPERIMENT_ROOT/results/latest" \
  "$@"
