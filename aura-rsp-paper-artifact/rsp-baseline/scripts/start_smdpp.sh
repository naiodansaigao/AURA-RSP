#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

PID_FILE="$RUNTIME_DIR/osmo-smdpp.pid"
LOG_FILE="$LOG_DIR/osmo-smdpp.log"

pid_alive() {
    local pid="$1"
    ps -p "$pid" -o pid= >/dev/null 2>&1
}

if [[ ! -x "$PYTHON" ]]; then
    echo "缺少 Python 虚拟环境：$VENV" >&2
    exit 1
fi
if [[ ! -f "$PKI_DIR/DPtls/CERT_S_SM_DP_TLS_NIST.der" ]]; then
    echo "缺少测试 PKI，请先运行 scripts/generate_test_pki.py" >&2
    exit 1
fi
if [[ -s "$PID_FILE" ]] && pid_alive "$(cat "$PID_FILE")"; then
    echo "osmo-smdpp 已运行，PID=$(cat "$PID_FILE")"
    exit 0
fi

if ! grep -Eq "^[[:space:]]*127\.0\.0\.1[[:space:]]+$SMDPP_HOST([[:space:]]|$)" /etc/hosts; then
    echo "127.0.0.1 $SMDPP_HOST" | sudo tee -a /etc/hosts >/dev/null
fi

if [[ "$(id -u)" -eq 0 ]]; then
    cd "$PYSIM_DIR"
    nohup "$PYTHON" ./osmo-smdpp.py -H 127.0.0.1 -p "$SMDPP_PORT" -c generated -m -v \
        >"$LOG_FILE" 2>&1 &
    echo "$!" >"$PID_FILE"
else
    sudo bash -c "cd '$PYSIM_DIR' && nohup '$PYTHON' ./osmo-smdpp.py -H 127.0.0.1 -p '$SMDPP_PORT' -c generated -m -v >'$LOG_FILE' 2>&1 & echo \$! >'$PID_FILE'"
fi

PID="$(cat "$PID_FILE")"
for _ in $(seq 1 90); do
    if ! pid_alive "$PID"; then
        echo "osmo-smdpp 启动失败，请查看 $LOG_FILE" >&2
        exit 1
    fi
    if curl -ksS --connect-timeout 1 --max-time 2 \
        "https://127.0.0.1:$SMDPP_PORT/" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! curl -ksS --connect-timeout 1 --max-time 2 \
    "https://127.0.0.1:$SMDPP_PORT/" >/dev/null 2>&1; then
    echo "osmo-smdpp 在 90 秒内未完成 HTTPS 就绪，请查看 $LOG_FILE" >&2
    exit 1
fi
echo "SMDPP_STARTED pid=$PID url=https://$SMDPP_HOST"
