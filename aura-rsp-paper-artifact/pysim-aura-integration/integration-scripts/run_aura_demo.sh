#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
trap '"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true' EXIT
"$ROOT/integration-scripts/bootstrap.sh"
"$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh"
"$PYTHON" -m pySim.esim.aura.client --mode normal |
    tee "$LOG_DIR/aura-integrated-client.log"
grep -q 'AURA_INTEGRATED_DOWNLOAD_PASS' "$LOG_DIR/aura-integrated-client.log"
cmp \
    "$ROOT/smdpp-data/upp/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der" \
    "$RUNTIME/software-euicc-output/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.aura.upp.der"
echo "AURA_PYSIM_INTEGRATION_ALL_PASS"
