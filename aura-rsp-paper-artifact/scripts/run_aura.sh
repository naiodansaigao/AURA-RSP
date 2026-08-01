#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/pysim-aura-integration/integration-scripts/run_aura_demo.sh"
