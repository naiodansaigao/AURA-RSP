#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

PID_FILE="$RUNTIME_DIR/osmo-smdpp.pid"
if [[ ! -s "$PID_FILE" ]]; then
    echo "osmo-smdpp 未运行"
    exit 0
fi

PID="$(cat "$PID_FILE")"
if ps -p "$PID" -o pid= >/dev/null 2>&1; then
    if [[ "$(id -u)" -eq 0 ]]; then
        kill "$PID"
    else
        sudo kill "$PID"
    fi
fi
rm -f "$PID_FILE"
echo "SMDPP_STOPPED"
