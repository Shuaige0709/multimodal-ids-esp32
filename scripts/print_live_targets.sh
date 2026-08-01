#!/usr/bin/env bash
# print_live_targets.sh - show live_state.json (for Kali if data/ is shared).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../host/attacks/netconfig.sh
source "${ROOT}/host/attacks/netconfig.sh"

if [[ ! -f "$LIVE_STATE_FILE" ]]; then
  echo "live_state.json not found: $LIVE_STATE_FILE"
  echo "On the collector host, start nids_collector.py (or session_windows.ps1)"
  exit 1
fi

IP="$(_json_field esp32_ip)"
MAC="$(_json_field esp32_mac)"
LH="$(get_label_host)"
CIP="$(_json_field collector_ip)"
echo "=== live targets ==="
echo "  ESP32 IP     : $IP"
echo "  ESP32 MAC    : $MAC"
echo "  label_host   : $LH   (Kali START/STOP — auto from live_state)"
echo "  collector_ip : $CIP  (ESP32 syslog path)"
echo
echo "If this live_state.json is the one Kali reads, attacks need no manual export."
echo "Otherwise paste:"
echo "----------------------------------------"
[[ -n "$IP" && "$IP" != "null" ]] && echo "export NIDS_ESP32_IP=$IP"
[[ -n "$MAC" && "$MAC" != "null" ]] && echo "export NIDS_ESP32_MAC=$MAC"
echo "export NIDS_LABEL_HOST=$LH"
echo "export NIDS_LABEL_PORT=${LABEL_PORT}"
echo "sudo ./host/attacks/attack_deauth.sh"
echo "----------------------------------------"
