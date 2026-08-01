#!/usr/bin/env bash
set -euo pipefail

EXPERIMENT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(CDPATH= cd -- "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"
source "$INTEGRATION_ROOT/integration-scripts/common.sh"
export PYTHONPATH="$INTEGRATION_ROOT${PYTHONPATH:+:$PYTHONPATH}"

"$PYTHON" "$EXPERIMENT_ROOT/demo.py" \
  --config "$EXPERIMENT_ROOT/config.json" \
  --output "$EXPERIMENT_ROOT/results/latest" \
  "$@"
