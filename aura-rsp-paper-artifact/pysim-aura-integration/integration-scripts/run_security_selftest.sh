#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"
cd "$ROOT"
"$PYTHON" -m pySim.esim.aura.selftest
