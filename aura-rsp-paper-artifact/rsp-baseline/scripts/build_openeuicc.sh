#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
OPENEUICC_DIR="$ROOT/third_party/openeuicc"

if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
    echo "Android SDK 未安装，请先运行 scripts/install_android_sdk.sh" >&2
    exit 1
fi

printf 'sdk.dir=%s\n' "$SDK_ROOT" >"$OPENEUICC_DIR/local.properties"
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"

cd "$OPENEUICC_DIR"
./gradlew --no-daemon :app:assembleDebug :app-unpriv:assembleDebug

find "$OPENEUICC_DIR/app/build/outputs/apk" \
     "$OPENEUICC_DIR/app-unpriv/build/outputs/apk" \
     -type f -name '*.apk' -print
echo "OPENEUICC_BUILD_PASS"
