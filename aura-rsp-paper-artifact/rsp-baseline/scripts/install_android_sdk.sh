#!/usr/bin/env bash
set -euo pipefail

SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
TOOLS_VERSION="15859902"
TOOLS_ZIP="commandlinetools-linux-${TOOLS_VERSION}_latest.zip"
TOOLS_URL="https://dl.google.com/android/repository/$TOOLS_ZIP"
TOOLS_SHA256="4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583"
DOWNLOAD_DIR="${TMPDIR:-/tmp}/rsp-baseline-android-sdk"
ZIP_PATH="$DOWNLOAD_DIR/$TOOLS_ZIP"

command -v unzip >/dev/null || {
    echo "缺少 unzip，请先运行：sudo apt install unzip" >&2
    exit 1
}

mkdir -p "$DOWNLOAD_DIR" "$SDK_ROOT/cmdline-tools"
if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
    if [[ ! -f "$ZIP_PATH" ]]; then
        curl -fL "$TOOLS_URL" -o "$ZIP_PATH"
    fi
    echo "$TOOLS_SHA256  $ZIP_PATH" | sha256sum --check -

    EXTRACT_DIR="$(mktemp -d "$DOWNLOAD_DIR/extracted.XXXXXX")"
    unzip -q "$ZIP_PATH" -d "$EXTRACT_DIR"
    mkdir -p "$SDK_ROOT/cmdline-tools/latest"
    cp -a "$EXTRACT_DIR/cmdline-tools/." "$SDK_ROOT/cmdline-tools/latest/"
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null || true
"$SDKMANAGER" --sdk_root="$SDK_ROOT" \
    "platform-tools" \
    "build-tools;35.0.0" \
    "platforms;android-31" \
    "platforms;android-32" \
    "platforms;android-34" \
    "platforms;android-35" \
    "ndk;26.1.10909125"

echo "ANDROID_SDK_READY root=$SDK_ROOT"
