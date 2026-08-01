#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This setup script must be run inside WSL2/Ubuntu or Linux." >&2
    exit 2
fi

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y \
        python3 python3-venv python3-dev build-essential git curl openssl \
        swig pcscd libpcsclite-dev
fi

bash "$ARTIFACT_ROOT/pysim-aura-integration/integration-scripts/install_deps.sh"
source "$ARTIFACT_ROOT/pysim-aura-integration/integration-scripts/common.sh"
"$PYTHON" -m pip install -r \
    "$ARTIFACT_ROOT/experiments/experiment-09-capability-downgrade/requirements-experiment9.lock"
bash "$ARTIFACT_ROOT/scripts/generate_standard_test_pki.sh"
bash "$ARTIFACT_ROOT/pysim-aura-integration/integration-scripts/bootstrap.sh"
echo "AURA_RSP_ARTIFACT_SETUP_PASS"
