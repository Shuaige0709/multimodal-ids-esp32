#!/usr/bin/env bash
# Optional Linux/Pi wrapper around nids_collector.py (checklist + wait).
# Preferred on Pi: just run
#   python3 host/collector/nids_collector.py
# Use this only if you want the printed checklist / --wait-esp32 helper.
#
# Usage:
#   ./scripts/bringup.sh
#   ./scripts/bringup.sh --wait-esp32 60
#   ./scripts/bringup.sh --no-collector
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../host/attacks/netconfig.sh
source "${ROOT}/host/attacks/netconfig.sh"

WAIT_SEC=0
NO_COLLECTOR=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait-esp32) WAIT_SEC="${2:-0}"; shift 2 ;;
    --no-collector) NO_COLLECTOR=1; shift ;;
    -h|--help)
      echo "Usage: $0 [--wait-esp32 SEC] [--no-collector]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

echo "============================================================"
echo " NIDS bring-up (collector on this Linux/Pi machine)"
echo "============================================================"
netconfig_summary
echo
echo "Firmware is usually flashed from Windows (ESP-IDF)."
echo "  On Windows: idf.py build flash monitor"
echo
echo "Notes:"
echo "  * This is the Pi/Linux twin of Windows session_windows.ps1"
echo "  * Attack labels must target THIS machine: export NIDS_LABEL_HOST=<this IP>"
echo "  * Kali attacks: host/attacks/*.sh only (no Python attack twins)"
echo "============================================================"

if [[ "$NO_COLLECTOR" -eq 1 ]]; then
  exit 0
fi

COLLECTOR="${ROOT}/host/collector/nids_collector.py"
echo
echo "Starting collector: ${COLLECTOR}"
echo "(Ctrl+C to stop)"
echo

python3 "$COLLECTOR" &
COLLECTOR_PID=$!

cleanup() {
  echo
  echo "Stopping collector (pid ${COLLECTOR_PID})..."
  kill "$COLLECTOR_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [[ "$WAIT_SEC" -gt 0 ]]; then
  echo "Waiting up to ${WAIT_SEC}s for ESP32 in live_state.json ..."
  deadline=$((SECONDS + WAIT_SEC))
  while (( SECONDS < deadline )); do
    ip="$(_json_field esp32_ip)"
    if [[ -n "$ip" && "$ip" != "null" ]]; then
      echo "  ESP32 live: IP=${ip} MAC=$(_json_field esp32_mac)"
      break
    fi
    sleep 1
  done
fi

wait "$COLLECTOR_PID"
