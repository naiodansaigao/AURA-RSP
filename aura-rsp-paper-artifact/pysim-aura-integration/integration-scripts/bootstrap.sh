#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$PYTHON" -m pySim.esim.aura.bootstrap
echo "AURA_INTEGRATED_BOOTSTRAP_READY"
