#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

cleanup() {
    "$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$PYTHON" -m py_compile \
    "$ROOT/pySim/esim/aura/lifecycle.py" \
    "$ROOT/pySim/esim/aura/lifecycle_client.py" \
    "$ROOT/pySim/esim/aura/service.py" \
    "$ROOT/osmo-smdpp.py"

cleanup
"$ROOT/integration-scripts/bootstrap.sh" >/dev/null
AURA_PERSISTENT_STORE=1 \
    "$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh" 9444 9443

"$PYTHON" -m pySim.esim.aura.lifecycle_client --full-demo |
    tee "$RESULT_DIR/aura-lifecycle-demo.txt"

grep -q AURA_INTEGRATED_LIFECYCLE_ALL_PASS \
    "$RESULT_DIR/aura-lifecycle-demo.txt"
echo "AURA_INTEGRATED_LIFECYCLE_DEMO_PASS"
