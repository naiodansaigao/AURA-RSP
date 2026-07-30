#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY="$ROOT/third_party"
OPENEUICC_COMMIT="2a85b8dad6000eea9dd622a468b7558e79933b2a"
LPAC_COMMIT="3ff35594ec15062a3ed10c3da1c26eb0a13390b8"
PYSIM_COMMIT="25e43e1540144be9026a2733bc3a4271b8fa7d25"

clone_at() {
    local url="$1"
    local dir="$2"
    local commit="$3"
    if [[ -d "$dir/.git" ]]; then
        git -C "$dir" fetch --all --tags
        git -C "$dir" checkout --detach "$commit"
        return
    fi
    if [[ -d "$dir" ]] && find "$dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        echo "USING_VENDORED_SOURCE dir=$dir commit=$commit"
        return
    fi
    if [[ ! -d "$dir/.git" ]]; then
        git clone "$url" "$dir"
    fi
    git -C "$dir" fetch --all --tags
    git -C "$dir" checkout --detach "$commit"
}

mkdir -p "$THIRD_PARTY"
clone_at https://github.com/estkme-group/openeuicc.git "$THIRD_PARTY/openeuicc" "$OPENEUICC_COMMIT"
if [[ -d "$THIRD_PARTY/openeuicc/.git" ]]; then
    git -C "$THIRD_PARTY/openeuicc" submodule update --init --recursive
fi
clone_at https://github.com/estkme-group/lpac.git "$THIRD_PARTY/lpac" "$LPAC_COMMIT"
if [[ -d "$THIRD_PARTY/lpac/.git" ]]; then
    git -C "$THIRD_PARTY/lpac" submodule update --init --recursive
fi
clone_at https://gitea.osmocom.org/sim-card/pysim.git "$THIRD_PARTY/pysim" "$PYSIM_COMMIT"

echo "SOURCES_READY"
