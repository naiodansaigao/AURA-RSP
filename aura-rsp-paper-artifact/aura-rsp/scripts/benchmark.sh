#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

iterations="${1:-10}"
"$ROOT/scripts/start_aura.sh" >/dev/null
"$PYTHON" -m aura_rsp.benchmark --iterations "$iterations" --warmups 1 |
    tee "$LOG_DIR/benchmark.log"
grep -q "AURA_BASELINE_BENCHMARK_PASS" "$LOG_DIR/benchmark.log"
echo "BENCHMARK_REPORT=$ROOT/results/latest-benchmark.md"
