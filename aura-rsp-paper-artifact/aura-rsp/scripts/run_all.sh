#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$ROOT/scripts/stop_aura.sh" >/dev/null 2>&1 || true
"$ROOT/scripts/bootstrap.sh"
"$PYTHON" -m aura_rsp.selftest
"$ROOT/scripts/start_aura.sh"
"$ROOT/scripts/run_demo.sh" --reuse-ticket
echo "AURA_RSP_ALL_PASS"
