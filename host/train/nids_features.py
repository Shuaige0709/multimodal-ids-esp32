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
    "probe_packets",    # probe req/resp count
    "auth_packets",     # auth frames (EAP / auth proxy)
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

# Network-only subset (no host/HIDS state) - used for the fusion ablation study
# that quantifies how much the host-side (HIDS) features contribute.
NIDS_ONLY_FEATURES = [
    "total_packets", "packet_density",
    "beacon_packets", "deauth_packets", "probe_packets", "auth_packets",
    "rssi_mean", "rssi_var", "snr_mean",
]

# Host-only (HIDS) features.
HIDS_FEATURES = ["heap", "minheap", "reconn", "qpeak", "udpfail", "backlog"]

LABEL_COL = "label"
ATTACK_TYPE_COL = "attack_type"
WINDOW_START_COL = "window_start"
