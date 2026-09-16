"""Versioned RAW feature contract; deliberately separate from legacy model.h.

802.11 FC/address layout reference:
https://github.com/torvalds/linux/blob/master/include/linux/ieee80211.h
No payload decryption, IP parsing, FCS verification, or on-device export here.
"""
SCHEMA = "raw-windows-v1"
WIRELESS = [
    "packet_count", "packets_per_second", "mgmt_count", "data_count", "ctrl_count",
    "beacon_count", "deauth_count", "disassoc_count", "probe_count", "auth_count",
    "retry_ratio", "protected_ratio", "unique_transmitters", "unique_bssids",
    "frame_bytes", "length_mean", "length_max", "rssi_mean", "rssi_std",
    "snr_mean", "iat_mean_us",
]
HARDWARE = ["heap", "minheap", "largest_free_internal", "free_internal",
            "queue_depth", "pool_free", "connected"]
FEATURE_SETS = {"wireless": WIRELESS, "multimodal": WIRELESS + HARDWARE}


def parse_header(payload):
    """Parse only supported version-0 MAC headers. Never assume a fixed data header.

    Addresses remain bytes; BSSID is absent for 4-address/WDS and control frames.
    Minimum checks cover the header only, not subtype-specific bodies or FCS.
    """
    if len(payload) < 2:
        return None
    fc = int.from_bytes(payload[:2], "little")
    kind, subtype = (fc >> 2) & 3, (fc >> 4) & 15
    if fc & 3 or kind == 3:
        return None
    result = {"kind": kind, "subtype": subtype, "retry": bool(fc & 0x0800),
              "protected": bool(fc & 0x4000), "ta": None, "bssid": None}
    if kind == 1:
        # Limit support to known classic control subtypes. Wrapper/extension
        # frames need separate layouts and are deliberately marked unsupported.
        if subtype not in range(8, 16) or len(payload) < (10 if subtype in (12, 13) else 16):
            return None
        return result
    ds = (fc >> 8) & 3
    size = 24 + (6 if kind == 2 and ds == 3 else 0)
    if kind == 2 and subtype & 8:
        size += 2  # QoS control follows addr4 when present
        if fc & 0x8000:
            size += 4  # HT control for ordered QoS data
    if kind == 0 and ds:
        return None
    if len(payload) < size:
        return None
    result["ta"] = payload[10:16]
    if kind == 0 or ds == 0:
        result["bssid"] = payload[16:22]
    elif ds == 1:
        result["bssid"] = payload[4:10]
    elif ds == 2:
        result["bssid"] = payload[10:16]
    return result
