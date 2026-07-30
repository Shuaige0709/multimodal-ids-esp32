#!/usr/bin/env bash
# print_live_targets.sh - same as the PowerShell helper (for Kali if data/ is shared).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../host/attacks/netconfig.sh
source "${ROOT}/host/attacks/netconfig.sh"

if [[ ! -f "$LIVE_STATE_FILE" ]]; then
  echo "live_state.json not found: $LIVE_STATE_FILE"
  echo "On the collector host, start: ./scripts/bringup.sh   (or session_windows.ps1 on Windows)"
  exit 1
fi

IP="$(_json_field esp32_ip)"
MAC="$(_json_field esp32_mac)"
echo "=== live targets ==="
echo "  ESP32 IP  : $IP"
echo "  ESP32 MAC : $MAC"
echo
echo "Paste / eval on Kali:"
echo "----------------------------------------"
echo "export NIDS_ESP32_IP=$IP"
[[ -n "$MAC" && "$MAC" != "null" ]] && echo "export NIDS_ESP32_MAC=$MAC"
echo "export NIDS_LABEL_HOST=${LABEL_HOST}"
echo "export NIDS_LABEL_PORT=${LABEL_PORT}"
echo "sudo ./host/attacks/attack_deauth.sh"
echo "----------------------------------------"
