#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

OUT_DIR="$ROOT/runtime/standard/software-euicc-output"
CLIENT_LOG="$LOG_DIR/standard-integrated-client.log"
mkdir -p "$OUT_DIR"
"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
trap '"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true' EXIT
"$ROOT/integration-scripts/start_smdpp.sh" standard 9443

"$PYTHON" "$ROOT/contrib/es9p_client.py" \
    --url "https://testsmdpplus1.example.com:9443" \
    --resolve-host-to 127.0.0.1 \
    --server-ca-cert "$ROOT/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$ROOT/smdpp-data/generated/eUICC" \
    --euicc-certificate CERT_EUICC_ECDSA_NIST.der \
    --euicc-private-key SK_EUICC_ECDSA_NIST.pem \
    --eum-certificate ../EUM/CERT_EUM_ECDSA_NIST.der \
    --ci-certificate ../CertificateIssuer/CERT_CI_ECDSA_NIST.der \
    download \
    --matchingId TS48V2-SAIP2-1-NOBERTLV-UNIQUE \
    --output-path "$OUT_DIR" 2>&1 | tee "$CLIENT_LOG"

TRANSACTION_ID="$(
    grep -oE '"transactionId": "[A-F0-9]{32}"' "$CLIENT_LOG" |
    head -n 1 | cut -d'"' -f4
)"
ICCID="$(
    basename "$(find "$OUT_DIR" -maxdepth 1 -name '*.upp.der' \
        ! -name '*.standard.upp.der' | head -n 1)" .upp.der
)"
test -n "$TRANSACTION_ID"
test -n "$ICCID"

"$PYTHON" "$ROOT/contrib/es9p_client.py" \
    --url "https://testsmdpplus1.example.com:9443" \
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
    --iccid "$ICCID" 2>&1 | tee -a "$CLIENT_LOG"

grep -q 'SUCCESS: Storing files' "$CLIENT_LOG"
grep -q 'SHARED_INSTALL_RESULT' "$CLIENT_LOG"
cmp \
    "$ROOT/smdpp-data/upp/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der" \
    "$OUT_DIR/TS48V2-SAIP2-1-NOBERTLV-UNIQUE.standard.upp.der"
echo "STANDARD_PYSIM_INTEGRATION_ALL_PASS"
