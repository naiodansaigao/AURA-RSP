#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

ITERATIONS="${1:-10}"
WARMUPS="${2:-1}"
if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] ||
   ! [[ "$WARMUPS" =~ ^[0-9]+$ ]]; then
    echo "usage: $0 [positive-iterations] [nonnegative-warmups]" >&2
    exit 2
fi

"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
trap '"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true' EXIT
"$ROOT/integration-scripts/bootstrap.sh" >/dev/null
"$ROOT/integration-scripts/start_smdpp.sh" standard 9445
"$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh"

"$PYTHON" "$ROOT/integration-scripts/benchmark_legacy_workflow.py" \
    --iterations "$ITERATIONS" \
    --warmups "$WARMUPS"
