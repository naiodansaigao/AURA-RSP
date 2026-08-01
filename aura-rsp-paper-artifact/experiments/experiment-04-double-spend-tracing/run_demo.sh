#!/usr/bin/env bash
set -euo pipefail

EXPERIMENT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(CDPATH= cd -- "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"

# Reuse exactly the interpreter and dependency resolution of the integrated
# pySim/osmo-smdpp implementation.
source "$INTEGRATION_ROOT/integration-scripts/common.sh"

"$PYTHON" "$EXPERIMENT_ROOT/demo.py" \
  --config "$EXPERIMENT_ROOT/config.json" \
  --output "$EXPERIMENT_ROOT/results/latest" \
  "$@"
