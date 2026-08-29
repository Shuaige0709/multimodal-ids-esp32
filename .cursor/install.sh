#!/usr/bin/env bash
# Idempotent Cloud Agent environment bootstrap for the ESP32 multimodal NIDS repo.
#
# Provisions everything needed for the full development experience:
#   1. System build prerequisites (for ESP-IDF and the Python venv)
#   2. ESP-IDF v5.4 firmware toolchain  -> `idf.py build`
#   3. Python host-tooling virtualenv   -> collector / aggregation / training
#
# Safe to run repeatedly: existing tools are detected and reused.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IDF_VERSION="v5.4"
IDF_DIR="${IDF_PATH:-$HOME/esp/esp-idf}"

if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi

# --- 1. System prerequisites (idempotent) ------------------------------------
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq \
  git wget flex bison gperf \
  cmake ninja-build ccache \
  libffi-dev libssl-dev dfu-util libusb-1.0-0 \
  python3 python3-venv python3-pip

# --- 2. ESP-IDF firmware toolchain (idempotent) ------------------------------
if [ ! -d "$IDF_DIR/.git" ]; then
  mkdir -p "$(dirname "$IDF_DIR")"
  git clone -b "$IDF_VERSION" --depth 1 --recursive --shallow-submodules \
    https://github.com/espressif/esp-idf.git "$IDF_DIR"
fi
# The ESP-IDF installer refuses to run from inside an active virtualenv, so run
# it with a clean environment (the project venv is activated later, in step 3).
env -u VIRTUAL_ENV "$IDF_DIR/install.sh" esp32

# --- 3. Python host-tooling virtualenv ---------------------------------------
if [ ! -x "$REPO_ROOT/.venv/bin/python" ]; then
  python3 -m venv "$REPO_ROOT/.venv"
fi
# shellcheck disable=SC1091
. "$REPO_ROOT/.venv/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements.txt

# --- 4. Host attack + helper scripts executable (README "First clone" step) ---
chmod +x host/attacks/*.sh scripts/*.sh 2>/dev/null || true

echo
echo "Install complete."
echo "  Python tools:   . .venv/bin/activate           # then: python host/train/..."
echo "  ESP-IDF build:  . \"$IDF_DIR/export.sh\"          # then: idf.py build"
