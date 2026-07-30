#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$ROOT/scripts/stop_aura.sh" >/dev/null 2>&1 || true
"$ROOT/scripts/bootstrap.sh"
"$ROOT/scripts/start_aura.sh"

"$PYTHON" -m aura_rsp.client --mode normal \
    >"$LOG_DIR/test-normal.log"
grep -q "AURA_RSP_DOWNLOAD_PASS" "$LOG_DIR/test-normal.log"

"$PYTHON" -m aura_rsp.ticket >/dev/null
"$PYTHON" -m aura_rsp.client --mode replay-auth \
    >"$LOG_DIR/test-replay.log"
grep -q "AURA_RSP_DOWNLOAD_PASS" "$LOG_DIR/test-replay.log"
grep -q '"auth_replay_cached": true' "$LOG_DIR/test-replay.log"

"$PYTHON" -m aura_rsp.ticket >/dev/null
"$PYTHON" -m aura_rsp.client --mode tamper-proof \
    >"$LOG_DIR/test-tamper-proof.log"
grep -q "AURA_TAMPER_PROOF_REJECTED" "$LOG_DIR/test-tamper-proof.log"

"$PYTHON" -m aura_rsp.ticket >/dev/null
"$PYTHON" -m aura_rsp.client --mode tamper-bind \
    >"$LOG_DIR/test-tamper-bind.log"
grep -q "AURA_TAMPER_BIND_REJECTED" "$LOG_DIR/test-tamper-bind.log"

"$PYTHON" -m aura_rsp.ticket >/dev/null
"$PYTHON" -m aura_rsp.client --mode normal \
    >"$LOG_DIR/test-double-spend-first.log"
"$PYTHON" -m aura_rsp.client --mode double-spend \
    >"$LOG_DIR/test-double-spend-second.log"
grep -q "AURA_DOUBLE_SPEND_TRACE_PASS" \
    "$LOG_DIR/test-double-spend-second.log"
grep -q "89049032123451234512345678901235" \
    "$LOG_DIR/test-double-spend-second.log"

cmp "$RUNTIME_DIR/profile.der" \
    "$RUNTIME_DIR/software-euicc-output/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.aura.upp.der"
"$PYTHON" -m aura_rsp.validation_report \
    >"$LOG_DIR/validation-report.log"
grep -q "AURA_VALIDATION_REPORT_PASS" "$LOG_DIR/validation-report.log"
echo "AURA_SECURITY_AND_DOWNLOAD_TESTS_PASS"
