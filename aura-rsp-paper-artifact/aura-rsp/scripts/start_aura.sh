#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

SMDPP_PID_FILE="$RUNTIME_DIR/aura-smdpp.pid"
RELAY_PID_FILE="$RUNTIME_DIR/aura-relay.pid"

pid_alive() {
    [[ -n "$1" ]] && ps -p "$1" -o pid= >/dev/null 2>&1
}

if [[ ! -f "$RUNTIME_DIR/server-public.json" ]]; then
    echo "缺少 AURA 运行配置，请先执行 scripts/bootstrap.sh" >&2
    exit 1
fi

if [[ -s "$SMDPP_PID_FILE" ]] && pid_alive "$(cat "$SMDPP_PID_FILE")"; then
    echo "AURA SM-DP+ 已运行，PID=$(cat "$SMDPP_PID_FILE")"
else
    nohup "$PYTHON" -m aura_rsp.server \
        >"$LOG_DIR/aura-smdpp-console.log" 2>&1 &
    echo "$!" >"$SMDPP_PID_FILE"
fi

for _ in $(seq 1 60); do
    if curl -fsS --connect-timeout 1 --max-time 2 \
        --cacert "$RUNTIME_DIR/pki/ca.pem" \
        --cert "$RUNTIME_DIR/pki/relay-client.pem" \
        --key "$RUNTIME_DIR/pki/relay-client-key.pem" \
        "https://127.0.0.1:9443/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
curl -fsS \
    --cacert "$RUNTIME_DIR/pki/ca.pem" \
    --cert "$RUNTIME_DIR/pki/relay-client.pem" \
    --key "$RUNTIME_DIR/pki/relay-client-key.pem" \
    "https://127.0.0.1:9443/health" >/dev/null

if [[ -s "$RELAY_PID_FILE" ]] && pid_alive "$(cat "$RELAY_PID_FILE")"; then
    echo "AURA Privacy Relay 已运行，PID=$(cat "$RELAY_PID_FILE")"
else
    nohup "$PYTHON" -m aura_rsp.relay \
        >"$LOG_DIR/aura-relay-console.log" 2>&1 &
    echo "$!" >"$RELAY_PID_FILE"
fi

for _ in $(seq 1 60); do
    if curl -fsS --connect-timeout 1 --max-time 2 \
        --cacert "$RUNTIME_DIR/pki/ca.pem" \
        "https://127.0.0.1:9444/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
curl -fsS --cacert "$RUNTIME_DIR/pki/ca.pem" \
    "https://127.0.0.1:9444/health" >/dev/null

echo "AURA_SERVICES_STARTED smdpp=$(cat "$SMDPP_PID_FILE") relay=$(cat "$RELAY_PID_FILE")"
