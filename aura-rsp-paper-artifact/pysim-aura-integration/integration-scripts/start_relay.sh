#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

PID_FILE="$RUNTIME/privacy-relay.pid"
LOG_FILE="$LOG_DIR/privacy-relay.log"
if [[ -s "$PID_FILE" ]] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
    echo "AURA_PR_ALREADY_RUNNING pid=$(cat "$PID_FILE")"
    exit 0
fi
nohup "$PYTHON" -m pySim.esim.aura.relay \
    --host 127.0.0.1 --port 9444 >"$LOG_FILE" 2>&1 &
echo "$!" >"$PID_FILE"
PID="$(cat "$PID_FILE")"
for _ in $(seq 1 60); do
    if ! ps -p "$PID" >/dev/null 2>&1; then
        echo "Privacy Relay failed; see $LOG_FILE" >&2
        exit 1
    fi
    if curl -ksS --connect-timeout 1 --max-time 2 \
        "https://127.0.0.1:9444/health" >/dev/null 2>&1; then
        echo "AURA_PR_READY pid=$PID port=9444"
        exit 0
    fi
    sleep 1
done
echo "Privacy Relay readiness timeout; see $LOG_FILE" >&2
exit 1
