#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NUMBER="${1:-}"
shift || true

if [[ ! "$NUMBER" =~ ^([1-9]|1[0-3])$ ]]; then
    echo "usage: $0 EXPERIMENT_NUMBER_1_TO_13 [experiment arguments...]" >&2
    exit 2
fi

printf -v PREFIX 'experiment-%02d-' "$NUMBER"
mapfile -t MATCHES < <(find "$ROOT/experiments" -mindepth 1 -maxdepth 1 -type d -name "${PREFIX}*" | sort)
if [[ "${#MATCHES[@]}" -ne 1 ]]; then
    echo "Expected exactly one directory matching ${PREFIX}*, found ${#MATCHES[@]}." >&2
    exit 3
fi

echo "RUNNING_EXPERIMENT=$NUMBER"
exec bash "${MATCHES[0]}/run_demo.sh" "$@"
