#!/usr/bin/env bash
# Usage: bash scripts/bringup.sh --port /dev/ttyUSB0 --label normal --standby
# Legacy: bash scripts/bringup.sh --mode legacy --wait-esp32 60
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${NIDS_PYTHON:-python3}"
if [[ -z "${NIDS_PYTHON:-}" && -x "$ROOT/.venv-raw/bin/python" ]]; then
  PYTHON="$ROOT/.venv-raw/bin/python"
fi
exec "$PYTHON" "$ROOT/scripts/bringup.py" "$@"
