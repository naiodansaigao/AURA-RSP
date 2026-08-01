#!/usr/bin/env bash
set -euo pipefail
# Run one Standard RSP transaction against an already running osmo-smdpp.
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

OUT_DIR="$ROOT/runtime/standard/software-euicc-output"
RUN_LOG="${1:-$LOG_DIR/standard-once.log}"
STANDARD_PORT="${STANDARD_PORT:-9443}"
mkdir -p "$OUT_DIR" "$(dirname "$RUN_LOG")"

PYSIM_ES9P_LOG_LEVEL="${PYSIM_ES9P_LOG_LEVEL:-WARNING}" \
"$PYTHON" "$ROOT/contrib/es9p_client.py" \
    --url "https://testsmdpplus1.example.com:${STANDARD_PORT}" \
    --resolve-host-to 127.0.0.1 \
    --server-ca-cert "$ROOT/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$ROOT/smdpp-data/generated/eUICC" \
    --euicc-certificate CERT_EUICC_ECDSA_NIST.der \
    --euicc-private-key SK_EUICC_ECDSA_NIST.pem \
    --eum-certificate ../EUM/CERT_EUM_ECDSA_NIST.der \
    --ci-certificate ../CertificateIssuer/CERT_CI_ECDSA_NIST.der \
    download-install \
    --matchingId TS48V2-SAIP2-1-NOBERTLV-UNIQUE \
    --output-path "$OUT_DIR" >"$RUN_LOG" 2>&1

grep -q 'SUCCESS: Storing files' "$RUN_LOG"
grep -q 'SHARED_INSTALL_RESULT' "$RUN_LOG"
RESULT_LINE="$(grep -m1 '^STANDARD_INTEGRATED_RESULT=' "$RUN_LOG")"
test -n "$RESULT_LINE"
printf '%s\n' "${RESULT_LINE#STANDARD_INTEGRATED_RESULT=}"
