#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

BUILD_DIR="$ROOT/build/lpac"
CMAKE_BIN="${CMAKE_BIN:-$VENV/bin/cmake}"
if [[ ! -x "$CMAKE_BIN" ]]; then
    CMAKE_BIN="$(command -v cmake)"
fi

"$CMAKE_BIN" -S "$LPAC_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DSTANDALONE_MODE=ON \
    -DLPAC_WITH_APDU_PCSC=ON \
    -DLPAC_WITH_HTTP_CURL=ON
"$CMAKE_BIN" --build "$BUILD_DIR" --parallel

LPAC_BIN="$(find "$BUILD_DIR" -type f -name lpac -perm -u+x | head -n 1)"
test -n "$LPAC_BIN"
file "$LPAC_BIN" | grep -q "ELF 64-bit"
test -f "$BUILD_DIR/driver/driver_apdu_pcsc.so"
test -f "$BUILD_DIR/driver/driver_http_curl.so"
ldd "$BUILD_DIR/driver/driver_apdu_pcsc.so" | grep -q "libpcsclite"
ldd "$BUILD_DIR/driver/driver_http_curl.so" | grep -q "libcurl"
echo "LPAC_BUILD_OK=$LPAC_BIN"
