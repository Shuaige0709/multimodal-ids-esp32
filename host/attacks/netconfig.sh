#!/usr/bin/env bash
# netconfig.sh - shared resolver for Kali attack scripts.
# Source this file:  source "$(dirname "$0")/netconfig.sh"
#
# Env overrides (same names as the Python netconfig):
#   NIDS_ESP32_IP, NIDS_ESP32_MAC, NIDS_GATEWAY_IP, NIDS_BSSID,
#   NIDS_LABEL_HOST, NIDS_LABEL_PORT, NIDS_SSID,
#   NIDS_WIFI_IFACE, NIDS_MON_IFACE

# Project root = host/attacks/../..
_ATTACKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${_ATTACKS_DIR}/../.." && pwd)"
LIVE_STATE_FILE="${PROJECT_ROOT}/data/live_state.json"

# Ports / Wi-Fi names (LABEL_HOST is resolved lazily — see get_label_host)
LABEL_PORT="${NIDS_LABEL_PORT:-9999}"
SSID="${NIDS_SSID:-302}"
WIFI_IFACE="${NIDS_WIFI_IFACE:-wlan0}"
MON_IFACE="${NIDS_MON_IFACE:-wlan0mon}"

_json_field() {
  # $1 = field name
  local field="$1"
  if [[ ! -f "$LIVE_STATE_FILE" ]]; then
    echo ""
    return
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg f "$field" '.[$f] // empty' "$LIVE_STATE_FILE" 2>/dev/null
  else
    python3 - "$LIVE_STATE_FILE" "$field" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    print(json.load(fh).get(sys.argv[2]) or "")
PY
  fi
}

get_label_host() {
  # Priority: explicit env > live_state.label_host > legacy default.
  # Do not fall back to collector_ip (Wi-Fi/syslog path) — old Python netconfig
  # always targeted host-only via NIDS_LABEL_HOST / hardcoded default.
  if [[ -n "${NIDS_LABEL_HOST:-}" ]]; then
    echo "$NIDS_LABEL_HOST"
    return 0
  fi
  local h
  h="$(_json_field label_host)"
  if [[ -n "$h" && "$h" != "null" ]]; then
    echo "$h"
    return 0
  fi
  # Fallback when live_state missing — match common VMnet1 host (.124). Override: NIDS_LABEL_HOST
  echo "192.168.124.1"
}

# Back-compat name used by older snippets (resolved once at source time if file exists)
LABEL_HOST="$(get_label_host)"

get_esp32_ip() {
  local ip="${NIDS_ESP32_IP:-$(_json_field esp32_ip)}"
  if [[ -z "$ip" || "$ip" == "null" ]]; then
    echo "[netconfig] ESP32 IP unknown. Start the collector so it writes data/live_state.json, or export NIDS_ESP32_IP." >&2
    return 1
  fi
  echo "$ip"
}

get_esp32_mac() {
  local mac="${NIDS_ESP32_MAC:-$(_json_field esp32_mac)}"
  if [[ -z "$mac" || "$mac" == "null" ]]; then
    echo "[netconfig] ESP32 MAC unknown. Export NIDS_ESP32_MAC or ensure firmware reports host_mac." >&2
    return 1
  fi
  echo "$mac"
}

get_gateway_ip() {
  if [[ -n "${NIDS_GATEWAY_IP:-}" ]]; then
    echo "$NIDS_GATEWAY_IP"
    return 0
  fi
  local ip
  ip="$(get_esp32_ip)" || return 1
  echo "${ip%.*}.1"
}

# Short airodump on monitor iface → print "BSSID CHANNEL" for SSID.
# Phone hotspots rotate BSSID; live_state is often stale — prefer this for deauth.
airodump_find_ap() {
  local mon="${1:-$MON_IFACE}"
  local essid="${2:-$SSID}"
  local sec="${NIDS_AIRODUMP_SEC:-10}"
  local tmpdir csv bssid ch

  if ! command -v airodump-ng >/dev/null 2>&1; then
    echo "[netconfig] airodump-ng not found" >&2
    return 1
  fi
  if ! ip link show "$mon" >/dev/null 2>&1; then
    echo "[netconfig] monitor iface '$mon' missing for airodump" >&2
    return 1
  fi

  tmpdir="$(mktemp -d)"
  echo "[netconfig] airodump ${sec}s on ${mon} for ESSID '${essid}' ..." >&2
  # timeout may return 124; CSV may still be written
  timeout "$sec" airodump-ng --essid "$essid" -w "${tmpdir}/scan" --output-format csv \
    "$mon" >/dev/null 2>&1 || true

  csv="$(ls -1 "${tmpdir}"/scan-*.csv 2>/dev/null | head -n1 || true)"
  if [[ -z "${csv:-}" || ! -s "$csv" ]]; then
    echo "[netconfig] airodump produced no CSV (AP quiet / wrong iface?)" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  # airodump CSV: AP section first; fields: BSSID,..., channel, ..., ESSID
  local pair
  set +e
  pair="$(python3 - "$csv" "$essid" <<'PY'
import csv, sys
path, essid = sys.argv[1], sys.argv[2]
best = None  # (power, bssid, channel) — power is negative dBm; pick strongest
with open(path, newline="", encoding="utf-8", errors="replace") as fh:
    rows = csv.reader(fh)
    for row in rows:
        if not row:
            break  # end of AP section
        if row[0].strip() == "BSSID":
            continue
        if len(row) < 14:
            continue
        bssid = row[0].strip()
        try:
            ch = int(str(row[3]).strip())
        except ValueError:
            continue
        ess = row[13].strip()
        if ess != essid:
            continue
        try:
            pwr = int(str(row[8]).strip())
        except ValueError:
            pwr = -999
        if best is None or pwr > best[0]:
            best = (pwr, bssid, ch)
if not best:
    sys.exit(1)
print(best[1], best[2])
PY
)"
  local py_rc=$?
  set -e
  rm -rf "$tmpdir"
  if [[ "$py_rc" -ne 0 || -z "${pair:-}" ]]; then
    echo "[netconfig] ESSID '${essid}' not seen in airodump window" >&2
    return 1
  fi
  bssid="${pair%% *}"
  ch="${pair##* }"
  echo "[netconfig] airodump match: BSSID=${bssid} channel=${ch}" >&2
  echo "${bssid} ${ch}"
}

resolve_bssid() {
  if [[ -n "${NIDS_BSSID:-}" ]]; then
    echo "$NIDS_BSSID"
    return 0
  fi
  # Prefer AP BSSID learned by ESP32 firmware (written into live_state.json)
  local from_live
  from_live="$(_json_field ap_bssid)"
  if [[ -n "$from_live" && "$from_live" != "null" && "$from_live" != "00:00:00:00:00:00" ]]; then
    echo "$from_live"
    return 0
  fi
  local scan bssid
  if command -v iw >/dev/null 2>&1; then
    scan="$(iw dev "$WIFI_IFACE" scan 2>/dev/null || true)"
  else
    scan="$(iwlist "$WIFI_IFACE" scan 2>/dev/null || true)"
  fi
  # Prefer iw "BSS xx:xx ... / SSID: name" pairing
  bssid="$(printf '%s\n' "$scan" | awk -v ssid="$SSID" '
    /^BSS / { mac=$2; sub(/\(.*/,"",mac) }
    /SSID: / {
      line=$0; sub(/^.*SSID: /,"",line)
      if (line == ssid) { print mac; exit }
    }
    /ESSID:/ {
      line=$0; sub(/^.*ESSID:/,"",line); gsub(/"/,"",line)
      if (line == ssid) { print mac; exit }
    }
  ')"
  if [[ -z "$bssid" ]]; then
    echo "[netconfig] could not resolve BSSID for SSID '$SSID'. Export NIDS_BSSID or wait for live_state.ap_bssid." >&2
    return 1
  fi
  echo "$bssid"
}

# Ping label host; Mode P: try restoring 10.0.0.0/24 via Windows if needed.
# UDP labels have no ACK — this only proves L3 reachability, not that collector printed START.
ensure_label_path() {
  local host iface gw
  host="$(get_label_host)"
  iface="${NIDS_HOSTONLY_IFACE:-eth0}"
  gw="${NIDS_WIN_GATEWAY:-192.168.124.1}"

  if [[ -z "$host" ]]; then
    echo "[netconfig] ERROR: empty label host — export NIDS_LABEL_HOST=10.0.0.2" >&2
    return 1
  fi

  if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
    echo "[netconfig] label host reachable: ${host}:${LABEL_PORT} (ICMP OK; watch collector for START/STOP)"
    return 0
  fi

  echo "[netconfig] WARN: cannot ping ${host} — trying Mode P host-only route via ${gw}" >&2
  if [[ "$host" == 10.0.0.* ]] && ip link show "$iface" >/dev/null 2>&1; then
    # prepare_wifi monitor flushes eth0; re-add addr+route best-effort
    if ! ip -4 addr show dev "$iface" | grep -q 'inet '; then
      ip addr add "${NIDS_HOSTONLY_IP:-192.168.124.50/24}" dev "$iface" 2>/dev/null || true
      ip link set "$iface" up 2>/dev/null || true
    fi
    ip route replace 10.0.0.0/24 via "$gw" dev "$iface" 2>/dev/null \
      && echo "[netconfig] installed route 10.0.0.0/24 via ${gw} dev ${iface}" >&2 \
      || true
  fi

  if ping -c 2 -W 1 "$host" >/dev/null 2>&1; then
    echo "[netconfig] label host reachable after route fix: ${host}:${LABEL_PORT}"
    return 0
  fi

  echo "[netconfig] ERROR: label host ${host} unreachable from Kali." >&2
  echo "[netconfig]   Collector must listen on that IP:9999 (Mode P → Pi eth0)." >&2
  echo "[netconfig]   Fix: nids-sync / export NIDS_LABEL_HOST=10.0.0.2" >&2
  echo "[netconfig]   Fix: sudo ip route replace 10.0.0.0/24 via ${gw} dev ${iface}" >&2
  echo "[netconfig]   Fix: ping ${host} from Kali before attacking." >&2
  return 1
}

send_label() {
  # send_label START|STOP [attack_type]
  # Same approach as pre-refactor Python netconfig: socket.sendto, a few repeats.
  # (Bash nc -u was the unreliable rewrite — not missing ACK protocol.)
  local status="$1"
  local attack_type="${2:-NONE}"
  local host repeats
  host="$(get_label_host)"
  repeats="${NIDS_LABEL_REPEATS:-3}"
  echo "[netconfig] label ${status} (${attack_type}) -> ${host}:${LABEL_PORT}"
  if [[ -z "$host" ]]; then
    echo "[netconfig] ERROR: empty label host — export NIDS_LABEL_HOST=10.0.0.2 (Pi) or sync live_state" >&2
    return 1
  fi

  python3 - "$host" "$LABEL_PORT" "$status" "$attack_type" "$repeats" <<'PY'
import json, socket, sys, time
host, port, status, atk, repeats = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
payload = json.dumps({
    "status": status,
    "attack_type": atk,
    "timestamp": time.time(),
}).encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(max(1, repeats)):
    try:
        sock.sendto(payload, (host, port))
    except OSError as e:
        print(f"[netconfig] label send failed: {e}", file=sys.stderr)
    time.sleep(0.2)
sock.close()
PY
}

netconfig_summary() {
  echo "=== netconfig (shell) ==="
  echo "  live_state : ${LIVE_STATE_FILE}"
  if [[ -f "$LIVE_STATE_FILE" ]]; then
    echo "  ESP32 IP   : $(_json_field esp32_ip)"
    echo "  ESP32 MAC  : $(_json_field esp32_mac)"
    echo "  label_host : $(_json_field label_host)  (from live_state)"
    echo "  collector  : $(_json_field collector_ip)  (syslog path)"
  else
    echo "  ESP32 IP   : (missing live_state.json)"
  fi
  echo "  SSID       : $SSID"
  echo "  Label      : $(get_label_host):${LABEL_PORT}  (env NIDS_LABEL_HOST overrides)"
  echo "  ifaces     : managed=$WIFI_IFACE  monitor=$MON_IFACE"
}

# If executed directly (not sourced), print summary
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  netconfig_summary
fi
