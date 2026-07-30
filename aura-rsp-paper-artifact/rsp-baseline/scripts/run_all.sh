#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT/scripts/stop_smdpp.sh"
if [[ ! -f "$ROOT/third_party/pysim/smdpp-data/generated/DPtls/CERT_S_SM_DP_TLS_NIST.der" ]]; then
    "$ROOT/scripts/generate_test_pki.py"
fi
"$ROOT/scripts/build_lpac.sh"
"$ROOT/scripts/start_smdpp.sh"
"$ROOT/scripts/run_software_demo.sh"
"$ROOT/scripts/check_baseline.sh"

echo "RSP_BASELINE_ALL_PASS"
