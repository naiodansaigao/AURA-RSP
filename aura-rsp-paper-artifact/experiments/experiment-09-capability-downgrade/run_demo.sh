#!/usr/bin/env bash
set -euo pipefail
EXPERIMENT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(CDPATH= cd -- "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"
source "$INTEGRATION_ROOT/integration-scripts/common.sh"
if ! "$PYTHON" -c "from kyber_py.ml_kem import ML_KEM_768" >/dev/null 2>&1; then
  echo "Missing kyber-py==1.2.0; run the integration dependency installer." >&2
  exit 2
fi
export PYTHONPATH="$INTEGRATION_ROOT${PYTHONPATH:+:$PYTHONPATH}"
"$PYTHON" "$EXPERIMENT_ROOT/demo.py" --config "$EXPERIMENT_ROOT/config.json" --output "$EXPERIMENT_ROOT/results/latest" "$@"
