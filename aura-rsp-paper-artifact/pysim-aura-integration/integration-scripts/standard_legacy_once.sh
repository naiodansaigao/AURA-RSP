#!/usr/bin/env bash
set -euo pipefail
# Legacy-compatible Standard workflow: preserve the historical two-client
# process boundary (download, then notification) against an already running
# server.  This is intentionally separate from the protocol-online benchmark.
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

OUT_DIR="$ROOT/runtime/standard/software-euicc-output"
RUN_LOG="${1:-$LOG_DIR/standard-legacy-once.log}"
STANDARD_PORT="${STANDARD_PORT:-9445}"
mkdir -p "$OUT_DIR" "$(dirname "$RUN_LOG")"
rm -f "$OUT_DIR"/*.der

"$PYTHON" "$ROOT/contrib/es9p_client.py" \
    --url "https://testsmdpplus1.example.com:${STANDARD_PORT}" \
    --resolve-host-to 127.0.0.1 \
    --server-ca-cert "$ROOT/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$ROOT/smdpp-data/generated/eUICC" \
    --euicc-certificate CERT_EUICC_ECDSA_NIST.der \
    --euicc-private-key SK_EUICC_ECDSA_NIST.pem \
    --eum-certificate ../EUM/CERT_EUM_ECDSA_NIST.der \
    --ci-certificate ../CertificateIssuer/CERT_CI_ECDSA_NIST.der \
    download \
    --matchingId TS48V2-SAIP2-1-NOBERTLV-UNIQUE \
    --output-path "$OUT_DIR" >"$RUN_LOG" 2>&1

TRANSACTION_ID="$(
    grep -oE '"transactionId": "[A-F0-9]{32}"' "$RUN_LOG" |
        head -n 1 | cut -d'"' -f4
)"
ICCID="$(
    basename "$(find "$OUT_DIR" -maxdepth 1 -name '*.upp.der' \
        ! -name '*.standard.upp.der' | head -n 1)" .upp.der
)"
test -n "$TRANSACTION_ID"
test -n "$ICCID"

"$PYTHON" "$ROOT/contrib/es9p_client.py" \
    --url "https://testsmdpplus1.example.com:${STANDARD_PORT}" \
    --resolve-host-to 127.0.0.1 \
    --server-ca-cert "$ROOT/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$ROOT/smdpp-data/generated/eUICC" \
    --euicc-certificate CERT_EUICC_ECDSA_NIST.der \
    --euicc-private-key SK_EUICC_ECDSA_NIST.pem \
    --eum-certificate ../EUM/CERT_EUM_ECDSA_NIST.der \
    --ci-certificate ../CertificateIssuer/CERT_CI_ECDSA_NIST.der \
    notification-install \
    --sequence-nr 1 \
    --transaction-id "$TRANSACTION_ID" \
    --smdpp-oid 2.999.10 \
    --isdp-aid a0000005591010ffffffff8900001000 \
    --sima-response bf2e00 \
    --iccid "$ICCID" >>"$RUN_LOG" 2>&1

grep -q 'SUCCESS: Storing files' "$RUN_LOG"
grep -q 'SHARED_INSTALL_RESULT' "$RUN_LOG"
cmp \
    "$ROOT/smdpp-data/upp/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der" \
    "$OUT_DIR/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.standard.upp.der"
echo "STANDARD_LEGACY_WORKFLOW_PASS"
