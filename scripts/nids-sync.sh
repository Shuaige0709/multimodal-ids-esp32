#!/usr/bin/env bash
# Sync data/live_state.json from the collector host (Mode P) onto Kali.
# Usage:
#   export NIDS_PI_HOST=user@10.0.0.2
#   ./scripts/nids-sync.sh
#   # or: ./scripts/nids-sync.sh user@10.0.0.2
#
# After sync, run attacks with sudo -E so NIDS_LABEL_HOST is visible if you export it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIVE="${ROOT}/data/live_state.json"
PI_HOST="${1:-${NIDS_PI_HOST:-}}"
PI_REMOTE="${NIDS_PI_LIVE_STATE:-~/project/multimodal-ids-esp32/data/live_state.json}"

if [[ -z "$PI_HOST" ]]; then
  echo "Usage: NIDS_PI_HOST=user@PI_IP ./scripts/nids-sync.sh" >&2
  echo "       ./scripts/nids-sync.sh user@PI_IP" >&2
  echo "Override remote path: NIDS_PI_LIVE_STATE=~/path/data/live_state.json" >&2
  exit 1
fi

mkdir -p "${ROOT}/data"
scp "${PI_HOST}:${PI_REMOTE}" "$LIVE"
# shellcheck source=../host/attacks/netconfig.sh
source "${ROOT}/host/attacks/netconfig.sh"
LH="$(get_label_host)"
echo ">>> Synced: $LIVE"
echo ">>> Paste on Kali (then use sudo -E for attacks):"
echo "export NIDS_LABEL_HOST=$LH"
"${ROOT}/scripts/print_live_targets.sh"
