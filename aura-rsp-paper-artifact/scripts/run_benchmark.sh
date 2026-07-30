#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ITERATIONS="${1:-10}"

bash "$ROOT/rsp-baseline/scripts/start_smdpp.sh"
cd "$ROOT/aura-rsp"
bash ./scripts/benchmark.sh "$ITERATIONS"

