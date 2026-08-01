#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ARTIFACT_ROOT/pysim-aura-integration/integration-scripts/common.sh"
cd "$ARTIFACT_ROOT/pysim-aura-integration"
"$PYTHON" ./contrib/generate_smdpp_certs.py
test -f smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem
test -f smdpp-data/generated/DPtls/SK_S_SM_DP_TLS_NIST.pem
test -f smdpp-data/generated/eUICC/SK_EUICC_ECDSA_NIST.pem
echo "STANDARD_TEST_PKI_GENERATION_PASS"
