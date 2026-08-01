#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

MODE="${1:-aura}"
PORT="${2:-9443}"
if [[ "$MODE" != "standard" && "$MODE" != "aura" ]]; then
    echo "usage: $0 standard|aura [port]" >&2
    exit 2
fi
PID_FILE="$RUNTIME/osmo-smdpp-${MODE}.pid"
LOG_FILE="$LOG_DIR/osmo-smdpp-${MODE}.log"
STORE_ARGS=(-m)
if [[ "$MODE" == "aura" && "${AURA_PERSISTENT_STORE:-0}" == "1" ]]; then
    STORE_ARGS=()
fi

if [[ -s "$PID_FILE" ]] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
    echo "OSMO_SMDPP_ALREADY_RUNNING mode=$MODE pid=$(cat "$PID_FILE")"
    exit 0
fi
(
    cd "$ROOT"
    nohup "$PYTHON" ./osmo-smdpp.py \
        -H 127.0.0.1 -p "$PORT" -c generated "${STORE_ARGS[@]}" \
        --rsp-mode "$MODE" --aura-root "$ROOT" \
        >"$LOG_FILE" 2>&1 &
    echo "$!" >"$PID_FILE"
)
PID="$(cat "$PID_FILE")"
for _ in $(seq 1 90); do
    if ! ps -p "$PID" >/dev/null 2>&1; then
        echo "osmo-smdpp failed; see $LOG_FILE" >&2
        exit 1
    fi
    if curl -ksS --connect-timeout 1 --max-time 2 \
        "https://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
        echo "OSMO_SMDPP_READY mode=$MODE pid=$PID port=$PORT"
        exit 0
    fi
    sleep 1
done
echo "osmo-smdpp readiness timeout; see $LOG_FILE" >&2
exit 1
