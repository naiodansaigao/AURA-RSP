#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

cleanup() {
    "$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
"$ROOT/integration-scripts/bootstrap.sh" >/dev/null
AURA_PERSISTENT_STORE=1 \
    "$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh" 9444 9443

"$PYTHON" -m pySim.esim.aura.client --mode normal \
    >"$RESULT_DIR/aura-lifecycle-recovery-download.txt"
"$PYTHON" -m pySim.esim.aura.lifecycle_client --prepare-delete-only \
    | tee "$RESULT_DIR/aura-lifecycle-recovery-prepare.txt"
grep -q AURA_LIFECYCLE_DELETE_PREPARED \
    "$RESULT_DIR/aura-lifecycle-recovery-prepare.txt"

# Simulate a server process crash/restart after the atomic pending-delete
# update but before commit-delete reaches the server.
cleanup
AURA_PERSISTENT_STORE=1 \
    "$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh" 9444 9443

"$PYTHON" -m pySim.esim.aura.lifecycle_client --resume-delete \
    | tee "$RESULT_DIR/aura-lifecycle-recovery-commit.txt"
grep -q AURA_LIFECYCLE_DELETE_RECOVERY_PASS \
    "$RESULT_DIR/aura-lifecycle-recovery-commit.txt"

echo "AURA_INTEGRATED_LIFECYCLE_RESTART_RECOVERY_PASS"
