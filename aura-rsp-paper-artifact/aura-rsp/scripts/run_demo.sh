#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

if [[ "${1:-}" != "--reuse-ticket" ]]; then
    "$PYTHON" -m aura_rsp.ticket
fi
"$PYTHON" -m aura_rsp.client --mode normal |
    tee "$LOG_DIR/aura-client.log"
grep -q "AURA_RSP_DOWNLOAD_PASS" "$LOG_DIR/aura-client.log"
cmp "$RUNTIME_DIR/profile.der" \
    "$RUNTIME_DIR/software-euicc-output/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.aura.upp.der"
echo "AURA_PROFILE_DOWNLOAD_EVIDENCE_OK"
