"""
Canonical feature definitions shared by the whole pipeline.

The order of WINDOW_FEATURES is the contract between:
  * aggregate_windows.py   (produces these columns)
  * analyze_and_train.py   (trains / exports the model on these columns)
  * model.h                (nids_window_features_t field order + nids_predict)
  * main.c firmware        (fills nids_window_features_t in this order)

Do not reorder without regenerating model.h and reflashing.
"""

# Full multimodal feature set for one 100 ms window.
WINDOW_FEATURES = [
    "total_packets",    # packets observed in the window
    "packet_density",   # total_packets / window_seconds (lambda)
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

# Wireless / RF-side features (no host state).
NIDS_ONLY_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "deauth_targeted",
    "probe_packets", "auth_packets", "seq_jump",
    "rssi_mean", "rssi_var", "snr_mean",
]

# Baseline wireless features before P0 WIDS additions (for ±WIDS ablation).
NIDS_BASELINE_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "probe_packets", "auth_packets",
    "rssi_mean", "rssi_var", "snr_mean",
]

# P0 WIDS-only delta (must match teammate confluence plan).
WIDS_P0_FEATURES = ["deauth_targeted", "seq_jump"]

# Host-only (HIDS) features.
HIDS_FEATURES = ["heap", "minheap", "reconn", "qpeak", "udpfail", "backlog"]

LABEL_COL = "label"
ATTACK_TYPE_COL = "attack_type"
WINDOW_START_COL = "window_start"

# Phase A acceptance defaults (override via check_dataset_balance.py CLI).
REQUIRED_ATTACK_TYPES = ("DEAUTH", "SYN_FLOOD", "ARP_SPOOF")
MIN_NORMAL_WINDOWS = 200
MIN_WINDOWS_PER_ATTACK = 150
MAX_HEAP_IMPORTANCE = 0.70  # export tree: heap must not dominate after rebalance
