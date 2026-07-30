#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${RSP_BASELINE_VENV:-$HOME/.venvs/rsp-baseline}"

sudo apt-get update
sudo apt-get install -y \
    build-essential git curl unzip openssl \
    python3 python3-dev python3-venv python3-pip \
    swig libusb-1.0-0 usbutils \
    pcscd pcsc-tools libpcsclite-dev \
    libcurl4-openssl-dev libssl-dev \
    openjdk-17-jdk-headless

python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -r "$ROOT/requirements-rsp.lock"
"$VENV/bin/pip" install --no-deps -e "$ROOT/third_party/pysim"

echo "DEPENDENCIES_READY venv=$VENV"
