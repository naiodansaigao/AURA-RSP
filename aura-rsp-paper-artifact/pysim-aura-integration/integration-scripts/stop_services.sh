#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

for file in "$RUNTIME"/privacy-relay.pid "$RUNTIME"/osmo-smdpp-*.pid; do
    [[ -e "$file" ]] || continue
    pid="$(cat "$file")"
    if ps -p "$pid" >/dev/null 2>&1; then
        kill "$pid"
        for _ in $(seq 1 20); do
            ps -p "$pid" >/dev/null 2>&1 || break
            sleep 0.1
        done
    fi
    rm -f "$file"
done
echo "PYSIM_AURA_INTEGRATED_SERVICES_STOPPED"
