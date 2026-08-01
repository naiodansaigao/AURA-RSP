#!/usr/bin/env bash
set -euo pipefail

EXPERIMENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(cd "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"
# Reuse the exact interpreter and dependencies of the integrated pySim build.
# shellcheck disable=SC1091
source "$INTEGRATION_ROOT/integration-scripts/common.sh"

"$PYTHON" "$EXPERIMENT_ROOT/demo.py" \
  --config "$EXPERIMENT_ROOT/config.json" \
  --output "$EXPERIMENT_ROOT/results/latest" \
  "$@"
