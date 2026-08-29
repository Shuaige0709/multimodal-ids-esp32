#!/usr/bin/env bash
# Idempotent repository bootstrap for the Cloud Agent environment.
#
# Sets up the Python host tooling (collector / aggregation / training) in a
# project-local virtualenv, matching the workflow documented in README.md.
# The ESP-IDF firmware toolchain lives in the base image/snapshot; activate it
# for a shell with:  . "$HOME/esp/esp-idf/export.sh"
set -euo pipefail

cd "$(dirname "$0")/.."

# Ensure the venv module is present (no-op once the base image has it).
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq python3-venv
fi

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

# Host attack + helper shell scripts must be executable after a fresh checkout
# (see README.md "First clone").
chmod +x host/attacks/*.sh scripts/*.sh 2>/dev/null || true

echo "Cloud Agent install complete. Activate the Python tools with: . .venv/bin/activate"
