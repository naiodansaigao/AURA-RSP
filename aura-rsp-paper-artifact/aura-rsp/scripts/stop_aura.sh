#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

for file in "$RUNTIME_DIR/aura-relay.pid" "$RUNTIME_DIR/aura-smdpp.pid"; do
    if [[ -s "$file" ]]; then
        pid="$(cat "$file")"
        if ps -p "$pid" -o pid= >/dev/null 2>&1; then
            kill "$pid"
        fi
        rm -f "$file"
    fi
done
echo "AURA_SERVICES_STOPPED"
