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
  # Priority: explicit env > live_state.label_host > live_state.collector_ip > legacy default
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
  h="$(_json_field collector_ip)"
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

send_label() {
  # send_label START|STOP [attack_type]
  local status="$1"
  local attack_type="${2:-NONE}"
  local ts msg host
  host="$(get_label_host)"
  ts="$(date +%s)"
  msg=$(printf '{"status":"%s","attack_type":"%s","timestamp":%s}' "$status" "$attack_type" "$ts")
  echo "[netconfig] label ${status} -> ${host}:${LABEL_PORT}"
  if command -v nc >/dev/null 2>&1; then
    printf '%s' "$msg" | nc -u -w1 "$host" "$LABEL_PORT" || true
  else
    printf '%s' "$msg" >"/dev/udp/${host}/${LABEL_PORT}" || true
  fi
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
