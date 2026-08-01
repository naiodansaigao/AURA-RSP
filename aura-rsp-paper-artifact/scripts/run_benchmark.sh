#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ITERATIONS="${1:-10}"
if [[ ! "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 [positive-iterations]" >&2
    exit 2
fi
if [[ ! -f "$ROOT/pysim-aura-integration/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem" ]]; then
    bash "$ROOT/scripts/generate_standard_test_pki.sh"
fi
exec bash "$ROOT/pysim-aura-integration/integration-scripts/benchmark.sh" "$ITERATIONS"
