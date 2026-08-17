"""
Canonical feature definitions shared by the whole pipeline.

The order of WINDOW_FEATURES is the contract between:
  * aggregate_windows.py   (produces these columns)
  * analyze_and_train.py   (trains / exports the model on these columns)
  * model.h                (nids_window_features_t field order + nids_predict)
  * main.c firmware        (fills nids_window_features_t in this order)

Do not reorder without regenerating model.h and reflashing.
"""

# Full multimodal feature set for one 100 ms tumbling window (non-overlapping).
# total_packets / packet_density MUST match on-device nids_window_features_t.
# Raw syslog is thinned (every N packets); firmware emits win_pkts / win_dens
# so aggregate_windows can prefer those over CSV row counts. Legacy CSVs without
# win_* fall back to row counts (offline != on-device; see density contract).
WINDOW_FEATURES = [
    "total_packets",    # packets in the window (prefer firmware win_pkts)
    "packet_density",   # lambda; prefer firmware win_dens
    "beacon_packets",   # 802.11 beacon count
    "deauth_packets",   # deauth + disassoc count
    "deauth_targeted",  # P0 WIDS: deauth/disassoc aimed at us or broadcast
    "probe_packets",    # probe req/resp count
    "auth_packets",     # auth frames (EAP / auth proxy)
    "seq_jump",         # P0 WIDS: sequence-number jumps in the window
    "rssi_mean",        # mean RSSI over the window
    "rssi_var",         # population variance of RSSI
    "snr_mean",         # mean SNR over the window
    "heap",             # HIDS: free heap at window end
    "minheap",          # HIDS: min free heap seen
    "reconn",           # HIDS: Wi-Fi reconnect count
    "qpeak",            # HIDS: packet queue peak depth
    "udpfail",          # HIDS: cumulative UDP send failures
    "backlog",          # HIDS: syslog backlog depth
]

# Sidecar HIDS: gateway MAC flips (syslog gw_flip). NOT in model.h until smoke passes.
HIDS_GW_FEATURES = [
    "gw_mac_flip",
]

# Wireless / RF-side features (no host state).
NIDS_ONLY_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "deauth_targeted",
    "probe_packets", "auth_packets", "seq_jump",
    "rssi_mean", "rssi_var", "snr_mean",
]

# Count / subtype wireless features only. RSSI/SNR often overfit one capture
# environment and cause IDLE false alarms after flash (domain shift).
NIDS_COUNTS_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "deauth_targeted",
    "probe_packets", "auth_packets", "seq_jump",
]

# Soft RF stats neutralized together with HIDS for --export-variant nids-counts.
RF_SOFT_FEATURES = ["rssi_mean", "rssi_var", "snr_mean"]

# Baseline wireless features before P0 WIDS additions (for ±WIDS ablation).
NIDS_BASELINE_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "probe_packets", "auth_packets",
    "rssi_mean", "rssi_var", "snr_mean",
]

# P0 WIDS-only delta
WIDS_P0_FEATURES = ["deauth_targeted", "seq_jump"]

# Host-only (HIDS) features.
HIDS_FEATURES = ["heap", "minheap", "reconn", "qpeak", "udpfail", "backlog"]

# HIDS without free-heap (heap often dominates the shallow DT).
HIDS_NO_HEAP_FEATURES = ["minheap", "reconn", "qpeak", "udpfail", "backlog"]

# Full multimodal minus heap — forces wireless + other host counters.
NO_HEAP_FEATURES = [f for f in WINDOW_FEATURES if f != "heap"]

LABEL_COL = "label"
ATTACK_TYPE_COL = "attack_type"
WINDOW_START_COL = "window_start"

# Phase A acceptance defaults (override via check_dataset_balance.py CLI).
REQUIRED_ATTACK_TYPES = ("DEAUTH", "SYN_FLOOD", "ARP_SPOOF")
# Phase C optional fourth type (enable via check_dataset_balance.py --with-auth).
PHASE_C_ATTACK_TYPES = ("AUTH_FLOOD",)
MIN_NORMAL_WINDOWS = 200
MIN_WINDOWS_PER_ATTACK = 150
MAX_HEAP_IMPORTANCE = 0.70  # export tree: heap must not dominate after rebalance

# RF sanity (promiscuous metadata). Positive RSSI with snr≈rssi usually means
# noise_floor≈0 / bad sample — drop from window means. Keep in sync with
# aggregate_windows.py; firmware still uses raw rx_ctrl until cleaned on-device.
RSSI_VALID_MIN = -100.0
RSSI_VALID_MAX = 0.0  # Espressif allows slight +; we treat >0 as dirty for training


def rf_sample_valid(rssi: float, snr=None) -> bool:
    """Return True if a per-packet RSSI(/SNR) sample should enter window stats."""
    if rssi != rssi:  # NaN
        return False
    if rssi < RSSI_VALID_MIN or rssi > RSSI_VALID_MAX:
        return False
    if snr is not None and snr == snr and rssi > 0 and abs(snr - rssi) < 1e-6:
        return False
    return True
