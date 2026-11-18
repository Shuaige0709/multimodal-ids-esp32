#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/netconfig.sh"
[[ "$EUID" == 0 && "$#" == 2 && "$1" == --bssid ]] || {
    echo 'Usage: sudo -E bash host/attacks/check_ap_pmf.sh --bssid AA:BB:CC:DD:EE:FF'; exit 1;
}
command -v iw >/dev/null
bash "$DIR/prepare_wifi.sh" managed
python3 "$DIR/check_ap_pmf.py" --interface "$WIFI_IFACE" --bssid "$2" \
    --output "$PROJECT_ROOT/data/demo_acceptance/pmf_scan_$(date +%Y%m%d_%H%M%S)"
