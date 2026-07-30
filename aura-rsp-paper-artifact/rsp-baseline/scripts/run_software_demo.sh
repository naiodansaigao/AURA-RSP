#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

OUT_DIR="$RUNTIME_DIR/software-euicc-output"
CLIENT_LOG="$LOG_DIR/es9p-client.log"
mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.der

"$PYTHON" "$PYSIM_DIR/contrib/es9p_client.py" \
    --url "https://$SMDPP_HOST" \
    --server-ca-cert "$PKI_DIR/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$PKI_DIR/eUICC" \
    --euicc-certificate CERT_EUICC_ECDSA_NIST.der \
    --euicc-private-key SK_EUICC_ECDSA_NIST.pem \
    --eum-certificate ../EUM/CERT_EUM_ECDSA_NIST.der \
    --ci-certificate ../CertificateIssuer/CERT_CI_ECDSA_NIST.der \
    download \
    --matchingId "$MATCHING_ID" \
    --output-path "$OUT_DIR" \
    2>&1 | tee "$CLIENT_LOG"

grep -q "Step 1: InitiateAuthentication" "$CLIENT_LOG"
grep -q "Step 2: AuthenticateClient" "$CLIENT_LOG"
grep -q "Step 3: GetBoundProfilePackage" "$CLIENT_LOG"
grep -q "SUCCESS: Storing files" "$CLIENT_LOG"

test "$(find "$OUT_DIR" -maxdepth 1 -name '*.upp.der' | wc -l)" -eq 1
test "$(find "$OUT_DIR" -maxdepth 1 -name '*.isdp.der' | wc -l)" -eq 1
test "$(find "$OUT_DIR" -maxdepth 1 -name '*.smr.der' | wc -l)" -eq 1

TRANSACTION_ID="$(
    grep -oE '"transactionId": "[A-F0-9]{32}"' "$CLIENT_LOG" |
    head -n 1 |
    cut -d'"' -f4
)"
ICCID="$(
    basename "$(find "$OUT_DIR" -maxdepth 1 -name '*.upp.der' | head -n 1)" .upp.der
)"
test -n "$TRANSACTION_ID"
test -n "$ICCID"

"$PYTHON" "$PYSIM_DIR/contrib/es9p_client.py" \
    --url "https://$SMDPP_HOST" \
    --server-ca-cert "$PKI_DIR/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
    --certificate-path "$PKI_DIR/eUICC" \
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
    --iccid "$ICCID" \
    2>&1 | tee -a "$CLIENT_LOG"

grep -q "POST /gsma/rsp2/es9plus/handleNotification HTTP/1.1\" 204" "$CLIENT_LOG"

echo "SOFTWARE_RSP_BASELINE_PASS"
echo "INSTALL_NOTIFICATION_PASS transactionId=$TRANSACTION_ID iccid=$ICCID"
echo "ACTIVATION_CODE=$ACTIVATION_CODE"
echo "OUTPUT_DIR=$OUT_DIR"
