#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$ROOT/pysim-aura-integration/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" ]]; then
    bash "$ROOT/scripts/generate_standard_test_pki.sh"
fi
exec bash "$ROOT/pysim-aura-integration/integration-scripts/run_all_tests.sh"
