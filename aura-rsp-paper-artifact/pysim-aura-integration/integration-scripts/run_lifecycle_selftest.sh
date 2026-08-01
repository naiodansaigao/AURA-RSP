#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$PYTHON" -m py_compile \
    "$ROOT/pySim/esim/aura/lifecycle.py" \
    "$ROOT/pySim/esim/aura/lifecycle_client.py" \
    "$ROOT/pySim/esim/aura/lifecycle_selftest.py" \
    "$ROOT/pySim/esim/aura/service.py" \
    "$ROOT/osmo-smdpp.py"

"$PYTHON" -m pySim.esim.aura.lifecycle_selftest |
    tee "$RESULT_DIR/aura-lifecycle-selftest.txt"

grep -q AURA_INTEGRATED_LIFECYCLE_SELFTEST_PASS \
    "$RESULT_DIR/aura-lifecycle-selftest.txt"
echo "AURA_INTEGRATED_LIFECYCLE_SELFTEST_PASS"
