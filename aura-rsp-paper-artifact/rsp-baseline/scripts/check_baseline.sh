#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

echo "HOST=$(uname -srmo)"
echo "PYTHON=$("$PYTHON" --version 2>&1)"
echo "SMDPP_HOST=$SMDPP_HOST"
echo "MATCHING_ID=$MATCHING_ID"
test -f "$PYSIM_DIR/smdpp-data/upp/$MATCHING_ID.der"

TLS_CERT="$PKI_DIR/DPtls/CERT_S_SM_DP_TLS_NIST.der"
openssl x509 -inform DER -in "$TLS_CERT" -noout -subject -issuer -dates

TLS_RESULT="$(
    openssl s_client \
        -connect "127.0.0.1:$SMDPP_PORT" \
        -servername "$SMDPP_HOST" \
        -CAfile "$PKI_DIR/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" \
        </dev/null 2>&1
)"
grep -q "Verify return code: 0 (ok)" <<<"$TLS_RESULT"
echo "TLS_VERIFY_OK"

if [[ -f "$LOG_DIR/es9p-client.log" ]] &&
   grep -q "SUCCESS: Storing files" "$LOG_DIR/es9p-client.log"; then
    echo "ES9P_DOWNLOAD_EVIDENCE_OK"
else
    echo "ES9P_DOWNLOAD_EVIDENCE_MISSING" >&2
    exit 1
fi

