#!/usr/bin/env bash
# One-way, no-forward ARP fixture for the team's owned ESP32 and gateway only.
# Keeps the gateway-side neighbor cache intact to isolate endpoint defense.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
source "${DIR}/netconfig.sh"
TARGET_IP="$(get_esp32_ip)"
GATEWAY_IP="$(get_gateway_ip)"
DURATION="${NIDS_ARP_DURATION:-60}"
[[ "$DURATION" =~ ^[0-9]+$ ]] && (( DURATION >= 10 && DURATION <= 180 )) || { echo 'Duration must be 10..180 seconds' >&2; exit 1; }
[[ "$TARGET_IP" != "$GATEWAY_IP" ]] || { echo 'Target and gateway must differ' >&2; exit 1; }
command -v arpspoof >/dev/null || { echo 'Install dsniff first' >&2; exit 1; }
if ip link show "$MON_IFACE" >/dev/null 2>&1; then
    echo 'Run prepare_wifi.sh managed and join the test AP first' >&2; exit 1
fi
ensure_label_path
ensure_wifi_associated "$WIFI_IFACE" "$SSID"
previous_forward="$(sysctl -n net.ipv4.ip_forward)"
pid=''
label_sent=0
cleanup() {
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    if [[ "$label_sent" == 1 ]]; then send_label STOP ARP_SPOOF || true; fi
    sysctl -w "net.ipv4.ip_forward=$previous_forward" >/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "One-way fixture: ESP32 $TARGET_IP, gateway $GATEWAY_IP, interface $WIFI_IFACE, ${DURATION}s"
echo "Forwarding disabled during this test; restored to $previous_forward on exit."
sysctl -w net.ipv4.ip_forward=0 >/dev/null
arpspoof -i "$WIFI_IFACE" -t "$TARGET_IP" "$GATEWAY_IP" >/dev/null 2>&1 &
pid=$!
sleep 1
kill -0 "$pid" 2>/dev/null || { echo 'ARP tool exited early' >&2; exit 1; }
send_label START ARP_SPOOF
label_sent=1
for ((i=0; i<DURATION; i++)); do
    sleep 1
    kill -0 "$pid" 2>/dev/null || { echo 'ARP tool exited during test' >&2; exit 1; }
done
echo 'Test finished; stopping spoof and restoring forwarding.'
