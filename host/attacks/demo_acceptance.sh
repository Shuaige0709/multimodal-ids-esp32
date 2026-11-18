#!/usr/bin/env bash
# Functional demo campaign on the team's own AP/ESP32. Not a training dataset.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/netconfig.sh"
[[ "$EUID" == 0 ]] || { echo 'Use sudo -E bash host/attacks/demo_acceptance.sh'; exit 1; }
for name in setsid arpspoof mdk4 aireplay-ng python3 timeout; do
    command -v "$name" >/dev/null || { echo "Missing tool: $name"; exit 1; }
done
python3 -c 'import scapy.all' || { echo 'Install python3-scapy first'; exit 1; }
# Reject unresolved targets before touching radio state.
get_esp32_ip >/dev/null
get_esp32_mac >/dev/null
: "${NIDS_BSSID:?Paste the Windows-generated setup block first}"
: "${NIDS_WIFI_CHANNEL:?Paste the Windows-generated setup block first}"
export NIDS_ARP_DURATION=45 NIDS_PROBE_FLOOD_SEC=30 NIDS_BEACON_FLOOD_SEC=30
export NIDS_EVIL_TWIN_SEC=30 NIDS_DISASSOC_SEC=30 NIDS_SKIP_AP_SCAN=1
export NIDS_DEMO_STRICT=1
LOG_DIR="$PROJECT_ROOT/data/demo_acceptance/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
printf 'start\tstop\tphase\ttool_exit\n' > "$LOG_DIR/phases.tsv"
child='' switched=0
cleanup() {
    if [[ -n "$child" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    if [[ "$switched" == 1 ]]; then bash "$DIR/prepare_wifi.sh" managed || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_phase() {
    local phase="$1" script="$2" start rc=0
    start="$(date -Iseconds)"
    echo "===== $phase ====="
    # Separate process group lets Ctrl+C terminate only this campaign's tools.
    setsid timeout --signal=TERM --kill-after=10s 180 bash "$DIR/$script" > "$LOG_DIR/$phase.log" 2>&1 &
    child=$!
    wait "$child" || rc=$?
    child=''
    printf '%s\t%s\t%s\t%s\n' "$start" "$(date -Iseconds)" "$phase" "$rc" >> "$LOG_DIR/phases.tsv"
    if (( rc != 0 )); then
        tail -n 12 "$LOG_DIR/$phase.log"
        echo "Tool failed in $phase; stopped rather than labeling it as passed."
        exit "$rc"
    fi
    echo 'Recovery observation: 30 seconds'
    sleep 30
}
bash "$DIR/prepare_wifi.sh" managed
ensure_wifi_associated "$WIFI_IFACE" "$SSID"
ensure_label_path
echo 'Baseline: 30 seconds. Keep the Windows UART dashboard running.'
sleep 30
run_phase arp_one_way arp_guard_test.sh
run_phase arp_two_way arpspoof.sh
switched=1
bash "$DIR/prepare_wifi.sh" monitor
run_phase probe attack_probe_flood.sh
run_phase beacon attack_beacon_flood.sh
run_phase twin attack_evil_twin.sh
run_phase deauth attack_deauth.sh
run_phase disassoc attack_disassoc.sh
echo "Campaign finished. Tool logs: $LOG_DIR"
echo 'Tool completion is not a protection verdict. Keep UART running another 30s, then Ctrl+C.'
