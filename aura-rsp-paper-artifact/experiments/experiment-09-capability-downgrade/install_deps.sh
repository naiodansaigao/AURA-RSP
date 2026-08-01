#!/usr/bin/env bash
set -euo pipefail
EXPERIMENT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_ROOT="$(CDPATH= cd -- "$EXPERIMENT_ROOT/../../pysim-aura-integration" && pwd)"
source "$INTEGRATION_ROOT/integration-scripts/common.sh"
"$PYTHON" -m pip install -r "$EXPERIMENT_ROOT/requirements-experiment9.lock"
"$PYTHON" -c "from kyber_py.ml_kem import ML_KEM_768; print('EXPERIMENT09_DEPENDENCIES_PASS')"
