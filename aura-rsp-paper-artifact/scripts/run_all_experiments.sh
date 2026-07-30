#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/results"
mkdir -p "$RESULTS"

passed=0
failed=0

for experiment in "$ROOT"/experiments/experiment-*; do
    [[ -d "$experiment" ]] || continue
    name="$(basename "$experiment")"
    log="$RESULTS/${name}.log"
    echo "===== $name ====="
    if bash "$experiment/run_demo.sh" 2>&1 | tee "$log"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
done

printf 'EXPERIMENTS_PASSED=%d\n' "$passed"
printf 'EXPERIMENTS_FAILED=%d\n' "$failed"

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi

echo "ALL_EXPERIMENTS_PASS"

