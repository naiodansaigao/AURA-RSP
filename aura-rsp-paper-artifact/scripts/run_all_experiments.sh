#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

for number in $(seq 1 13); do
    echo "===== EXPERIMENT $(printf '%02d' "$number") ====="
    bash "$ROOT/scripts/run_experiment.sh" "$number"
done

echo "ALL_13_EXPERIMENTS_PASS"
