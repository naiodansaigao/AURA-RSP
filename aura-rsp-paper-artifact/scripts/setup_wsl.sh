#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$ROOT/rsp-baseline/scripts/install_deps.sh"
bash "$ROOT/aura-rsp/scripts/install_deps.sh"
bash "$ROOT/experiments/experiment-09-capability-downgrade/install_deps.sh"

python3 "$ROOT/scripts/verify_artifact.py"
echo "ARTIFACT_SETUP_PASS"

