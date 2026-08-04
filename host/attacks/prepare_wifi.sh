#!/usr/bin/env bash
# prepare_wifi.sh - Kali Wi-Fi / Host-only prep (restored from archive/set_wifi.sh)
#
# Usage:
#   sudo ./host/attacks/prepare_wifi.sh monitor   # before deauth
#   sudo ./host/attacks/prepare_wifi.sh managed   # before SYN / ARP (after deauth)
#   sudo ./host/attacks/prepare_wifi.sh status
#
# Env overrides:
#   NIDS_WIFI_IFACE   default wlan0
#   NIDS_MON_IFACE    default wlan0mon
#   NIDS_WIFI_CHANNEL default 11
#   NIDS_HOSTONLY_IFACE default eth0   (VMnet1 side inside Kali)
#   NIDS_HOSTONLY_IP    default 192.168.124.50/24  (match host VMnet1; override if yours differs)
#   NIDS_SKIP_HOSTONLY=1  skip eth0 reconfiguration
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

WIFI_IFACE="${NIDS_WIFI_IFACE:-wlan0}"
MON_IFACE="${NIDS_MON_IFACE:-wlan0mon}"
# Channel: explicit env > live_state.json (ESP32-reported) > default 11
_LIVE_CH="$(_json_field channel 2>/dev/null || true)"
if [[ -n "${NIDS_WIFI_CHANNEL:-}" ]]; then
  CHANNEL="$NIDS_WIFI_CHANNEL"
elif [[ -n "${_LIVE_CH}" && "${_LIVE_CH}" != "null" && "${_LIVE_CH}" != "0" ]]; then
  CHANNEL="${_LIVE_CH}"
else
  CHANNEL="11"
fi
HOSTONLY_IFACE="${NIDS_HOSTONLY_IFACE:-eth0}"
HOSTONLY_CIDR="${NIDS_HOSTONLY_IP:-192.168.124.50/24}"
MODE="${1:-status}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[prepare_wifi] please run with sudo" >&2
    exit 1
  fi
}

iface_exists() {
  ip link show "$1" >/dev/null 2>&1
}

setup_hostonly() {
  if [[ "${NIDS_SKIP_HOSTONLY:-0}" == "1" ]]; then
    echo "[prepare_wifi] skip host-only (${HOSTONLY_IFACE})"
    return 0
  fi
  if ! iface_exists "$HOSTONLY_IFACE"; then
    echo "[prepare_wifi] WARN: ${HOSTONLY_IFACE} not found — check VMware Host-only (VMnet1)"
    return 0
  fi
  echo "[prepare_wifi] host-only ${HOSTONLY_IFACE} -> ${HOSTONLY_CIDR}"
  ip addr flush dev "$HOSTONLY_IFACE" 2>/dev/null || true
  ip addr add "$HOSTONLY_CIDR" dev "$HOSTONLY_IFACE"
  ip link set "$HOSTONLY_IFACE" up
  # Mode P: Pi eth0 is 10.0.0.2 behind Windows; flush drops this route every time.
  _win_gw="${NIDS_WIN_GATEWAY:-192.168.124.1}"
  if [[ "${HOSTONLY_CIDR}" == 192.168.124.* ]]; then
    ip route replace 10.0.0.0/24 via "${_win_gw}" dev "$HOSTONLY_IFACE" 2>/dev/null \
      && echo "[prepare_wifi] route 10.0.0.0/24 via ${_win_gw}" \
      || true
  fi
  echo "[prepare_wifi] label target should be reachable (often $(get_label_host))"
  ping -c 1 -W 1 "$(get_label_host)" >/dev/null 2>&1 \
    && echo "[prepare_wifi] ping $(get_label_host) OK" \
    || echo "[prepare_wifi] WARN: cannot ping $(get_label_host) — sync live_state or set NIDS_LABEL_HOST"
}

cmd_monitor() {
  need_root
  setup_hostonly
  echo "[prepare_wifi] enabling monitor on ${WIFI_IFACE} ..."
  airmon-ng check kill || true
  if iface_exists "$MON_IFACE"; then
    echo "[prepare_wifi] ${MON_IFACE} already present"
  else
    airmon-ng start "$WIFI_IFACE"
  fi
  # Some drivers name the mon iface differently; prefer existing mon*
  if ! iface_exists "$MON_IFACE"; then
    alt="$(ip -o link show | awk -F': ' '/mon/ {print $2; exit}')"
    if [[ -n "${alt:-}" ]]; then
      echo "[prepare_wifi] using detected mon iface: ${alt} (export NIDS_MON_IFACE=${alt})"
      MON_IFACE="$alt"
    fi
  fi
  iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null \
    || iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null \
    || echo "[prepare_wifi] WARN: could not set channel ${CHANNEL}"
  echo "==========================================="
  echo " Attack iface : ${MON_IFACE} (channel ${CHANNEL})"
  echo " Label path   : ${HOSTONLY_IFACE} ${HOSTONLY_CIDR} -> $(get_label_host):${LABEL_PORT}"
  echo " Next         : sudo ./host/attacks/attack_deauth.sh"
  echo " After deauth : sudo ./host/attacks/prepare_wifi.sh managed"
  echo "=== TO RECOVER internet (airmon kills NM) ==="
  echo " sudo airmon-ng stop ${MON_IFACE}"
  echo " sudo systemctl restart NetworkManager"
  echo " (or: sudo ./host/attacks/prepare_wifi.sh managed)"
  echo "==========================================="
}

cmd_managed() {
  need_root
  echo "[prepare_wifi] restoring managed mode ..."
  if iface_exists "$MON_IFACE"; then
    airmon-ng stop "$MON_IFACE" || true
  fi
  # airmon-ng check kill left NM dead — bring it back and unblock wifi
  rfkill unblock wifi 2>/dev/null || true
  if command -v systemctl >/dev/null 2>&1; then
    systemctl start NetworkManager 2>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true
  fi
  # Give NM a moment; ensure station iface exists and is up
  sleep 2
  if iface_exists "$WIFI_IFACE"; then
    ip link set "$WIFI_IFACE" up 2>/dev/null || true
  else
    echo "[prepare_wifi] WARN: ${WIFI_IFACE} missing — plug USB Wi-Fi / connect in VMware"
  fi

  setup_hostonly

  # Best-effort reconnect to lab hotspot (needs NM + password already saved, or wifi.powersave)
  if command -v nmcli >/dev/null 2>&1 && iface_exists "$WIFI_IFACE"; then
    echo "[prepare_wifi] trying nmcli connect '${SSID}' on ${WIFI_IFACE} ..."
    nmcli device set "$WIFI_IFACE" managed yes 2>/dev/null || true
    nmcli radio wifi on 2>/dev/null || true
    if nmcli -t -f NAME connection show | grep -qx "$SSID"; then
      nmcli connection up "$SSID" ifname "$WIFI_IFACE" 2>/dev/null \
        || nmcli device wifi connect "$SSID" ifname "$WIFI_IFACE" 2>/dev/null \
        || echo "[prepare_wifi] WARN: auto-connect failed — run nmcli manually (see below)"
    else
      nmcli device wifi connect "$SSID" ifname "$WIFI_IFACE" 2>/dev/null \
        || echo "[prepare_wifi] WARN: no saved connection for '${SSID}' — connect manually"
    fi
    sleep 1
    nmcli -t -f DEVICE,STATE,CONNECTION device status 2>/dev/null | head -n 10 || true
  fi

  echo "==========================================="
  echo " Managed iface : ${WIFI_IFACE} (SSID '${SSID}')"
  echo " Label path    : ${HOSTONLY_IFACE} -> $(get_label_host):${LABEL_PORT}"
  echo " If hotspot not up yet:"
  echo "   nmcli device wifi rescan"
  echo "   nmcli device wifi connect '${SSID}' ifname ${WIFI_IFACE}"
  echo " If ping Pi fails:"
  echo "   sudo ip route replace 10.0.0.0/24 via ${NIDS_WIN_GATEWAY:-192.168.124.1} dev ${HOSTONLY_IFACE}"
  echo " Next: sudo -E ./host/attacks/syn_flood.sh"
  echo "==========================================="
}

cmd_status() {
  echo "=== prepare_wifi status ==="
  echo " WIFI_IFACE=${WIFI_IFACE}  MON_IFACE=${MON_IFACE}  CHANNEL=${CHANNEL}"
  echo " HOSTONLY=${HOSTONLY_IFACE} ${HOSTONLY_CIDR}  LABEL=$(get_label_host):${LABEL_PORT}"
  ip -br link 2>/dev/null || true
  echo
  iwconfig 2>/dev/null | head -n 40 || true
}

case "$MODE" in
  monitor) cmd_monitor ;;
  managed|restore) cmd_managed ;;
  status) cmd_status ;;
  -h|--help)
    echo "Usage: sudo $0 {monitor|managed|status}"
    exit 0
    ;;
  *)
    echo "Unknown mode: $MODE (use monitor|managed|status)" >&2
    exit 1
    ;;
esac
