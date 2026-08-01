#!/usr/bin/env bash
set -euo pipefail
# Paper-facing benchmark: preserve the process-inclusive workflow boundary used
# by the original AURA-RSP latency table.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "$ROOT/integration-scripts/benchmark_legacy_workflow.sh" "$@"
