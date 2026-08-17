#!/usr/bin/env python3
"""
aggregate_windows.py - turn a per-packet capture into the 100 ms time-window
statistical features described in the report.

Each raw CSV row from nids_collector.py is one packet/heartbeat sample. This
script collapses them into fixed 100 ms epochs and emits the canonical window
feature set (see nids_features.WINDOW_FEATURES), producing the "Time-Window
Statistical Aggregation" representation. The same feature definitions are
computed on-device in the firmware, so the offline dataset and the deployed
model see identical features.

When raw rows include firmware win_pkts / win_dens, total_packets and
packet_density prefer those values (syslog is thinned; CSV row count != air).
Legacy captures without those columns keep counting CSV rows and warn.

Dependencies: standard library + numpy only (no pandas), to keep the pipeline
easy to reproduce on any machine.

Usage:
  python -m host.train.aggregate_windows
  python host/train/aggregate_windows.py data/raw/nids_dataset_*.csv
  python host/train/aggregate_windows.py --window-ms 100 --out data/windows/out.csv <inputs...>
"""
import argparse
import csv
import glob
import os
import sys
from collections import Counter, OrderedDict
from datetime import datetime

import numpy as np

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_RAW, DATA_WINDOWS, ensure_data_dirs  # noqa: E402
from host.train.nids_features import (  # noqa: E402
    WINDOW_FEATURES, HIDS_GW_FEATURES, LABEL_COL, ATTACK_TYPE_COL, WINDOW_START_COL,
    rf_sample_valid,
)


def _to_float(val, default=0.0):
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _majority_attack(values):
    vals = [v for v in values if v and v not in ("NONE", "nan")]
    if not vals:
        return "NONE"
    return Counter(vals).most_common(1)[0][0]


def aggregate_rows(rows, window_sec, density_source_stats=None):
    """Group per-packet rows into fixed windows and compute canonical features.

    Prefer firmware-emitted win_pkts / win_dens (same source as on-device
    nids_predict) when present; fall back to counting CSV rows (syslog-thinned).
    """
    windows = OrderedDict()  # bin_index -> list of rows
    for r in rows:
        ts = r.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        bin_index = int(dt.timestamp() // window_sec)
        windows.setdefault(bin_index, []).append((dt, r))

    used_fw = 0
    used_csv = 0
    out = []
    for bin_index in sorted(windows.keys()):
        entries = sorted(windows[bin_index], key=lambda x: x[0])
        group = [r for _, r in entries]
        csv_total = len(group)

        fw_pkts = []
        fw_dens = []
        for r in group:
            raw_pk = r.get("win_pkts")
            if raw_pk not in (None, ""):
                fw_pkts.append(_to_float(raw_pk))
            raw_dn = r.get("win_dens")
            if raw_dn not in (None, ""):
                fw_dens.append(_to_float(raw_dn))

        if fw_pkts:
            # Max over thinned samples in this bin ≈ closed-window peak when
            # syslog lands near a window boundary; mid-window samples are lower.
            total = int(max(fw_pkts))
            if fw_dens:
                density = float(max(fw_dens))
            else:
                density = total / window_sec if window_sec > 0 else float(total)
            used_fw += 1
        else:
            total = csv_total
            density = total / window_sec if window_sec > 0 else float(total)
            used_csv += 1

        rssi_all = np.array([_to_float(r.get("rssi")) for r in group], dtype=float)
        snr_all = np.array([_to_float(r.get("snr")) for r in group], dtype=float)
        rf_ok = np.array(
            [rf_sample_valid(float(a), float(b)) for a, b in zip(rssi_all, snr_all)],
            dtype=bool,
        )
        rssi = rssi_all[rf_ok]
        snr = snr_all[rf_ok]
        subs = [(r.get("subtype") or "").strip() for r in group]

        beacon = sum(1 for s in subs if s == "BEACON")
        deauth = sum(1 for s in subs if s in ("DEAUTH", "DISASSOC"))
        probe = sum(1 for s in subs if s.startswith("PROBE"))
        auth = sum(1 for s in subs if s == "AUTH")
        # P0 WIDS: prefer firmware-emitted flags; fall back to 0 on old CSVs
        deauth_tgt = sum(1 for r in group if int(_to_float(r.get("deauth_tgt"))) > 0)
        seq_jump = sum(1 for r in group if int(_to_float(r.get("seq_jump"))) > 0)

        last = group[-1]
        label = 1 if any(int(_to_float(r.get(LABEL_COL))) > 0 for r in group) else 0
        atk = _majority_attack([r.get(ATTACK_TYPE_COL, "NONE") for r in group])

        row = {
            WINDOW_START_COL: datetime.fromtimestamp(bin_index * window_sec).isoformat(),
            "total_packets": total,
            "packet_density": density,
            "beacon_packets": beacon,
            "deauth_packets": deauth,
            "deauth_targeted": deauth_tgt,
            "probe_packets": probe,
            "auth_packets": auth,
            "seq_jump": seq_jump,
            "gw_mac_flip": int(_to_float(last.get("gw_flip"))),
            # RF means use cleaned samples only (dirty → leave 0 / empty-window default)
            "rssi_mean": float(rssi.mean()) if len(rssi) else 0.0,
            "rssi_var": float(rssi.var()) if len(rssi) > 1 else 0.0,
            "snr_mean": float(snr.mean()) if len(snr) else 0.0,
            "heap": _to_float(last.get("heap")),
            "minheap": _to_float(last.get("minheap")),
            "reconn": _to_float(last.get("reconn")),
            "qpeak": _to_float(last.get("qpeak")),
            "udpfail": _to_float(last.get("udpfail")),
            "backlog": _to_float(last.get("backlog")),
            LABEL_COL: label,
            ATTACK_TYPE_COL: atk,
        }
        out.append(row)

    if density_source_stats is not None:
        density_source_stats["firmware"] = density_source_stats.get("firmware", 0) + used_fw
        density_source_stats["csv_rows"] = density_source_stats.get("csv_rows", 0) + used_csv
    return out


def main():
    ap = argparse.ArgumentParser(description="100 ms time-window aggregation")
    ap.add_argument("inputs", nargs="*", help="per-packet CSV files (default: newest nids_dataset_*.csv)")
    ap.add_argument("--window-ms", type=int, default=100)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    inputs = args.inputs
    if not inputs:
        ensure_data_dirs()
        candidates = sorted(glob.glob(os.path.join(DATA_RAW, "nids_dataset_*.csv")))
        if not candidates:
            raise SystemExit(f"No nids_dataset_*.csv found in {DATA_RAW} and no inputs given.")
        inputs = [candidates[-1]]
    else:
        expanded = []
        for pat in inputs:
            hits = glob.glob(pat)
            expanded.extend(hits if hits else [pat])
        inputs = expanded

    window_sec = args.window_ms / 1000.0
    all_windows = []
    density_stats = {"firmware": 0, "csv_rows": 0}
    for path in inputs:
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
        except OSError as e:
            print(f"  skip {path}: {e}")
            continue
        if not rows or "timestamp" not in rows[0]:
            print(f"  skip {path}: no 'timestamp' column")
            continue
        has_win = "win_pkts" in rows[0] and any(
            (r.get("win_pkts") not in (None, "")) for r in rows[:200]
        )
        w = aggregate_rows(rows, window_sec, density_source_stats=density_stats)
        src = "firmware win_pkts" if has_win else "CSV row count (legacy)"
        print(f"  {os.path.basename(path)}: {len(rows)} packets -> {len(w)} windows [{src}]")
        all_windows.extend(w)

    if not all_windows:
        raise SystemExit("Nothing aggregated.")

    if density_stats["firmware"] == 0 and density_stats["csv_rows"] > 0:
        print(
            "  WARN: no win_pkts in input - total_packets/packet_density from "
            "syslog-thinned CSV rows (offline != on-device). Flash firmware that "
            "emits win_pkts/win_dens for a correct contract."
        )
    elif density_stats["firmware"] > 0:
        print(
            f"  density source: firmware={density_stats['firmware']} windows, "
            f"legacy CSV fallback={density_stats['csv_rows']} windows"
        )

    out_path = args.out
    if not out_path:
        ensure_data_dirs()
        stamp = os.path.basename(inputs[-1]).replace("nids_dataset_", "").replace(".csv", "")
        out_path = os.path.join(DATA_WINDOWS, f"nids_windows_{stamp}.csv")

    cols = [WINDOW_START_COL] + WINDOW_FEATURES + HIDS_GW_FEATURES + [LABEL_COL, ATTACK_TYPE_COL]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for row in all_windows:
            writer.writerow({k: row[k] for k in cols})

    n_attack = sum(1 for r in all_windows if r[LABEL_COL] == 1)
    n_normal = len(all_windows) - n_attack
    atk_counts = Counter(r[ATTACK_TYPE_COL] for r in all_windows if r[LABEL_COL] == 1)
    dens_vals = [r["packet_density"] for r in all_windows]
    print(f"\nWrote {len(all_windows)} windows -> {out_path}")
    print(f"  normal windows: {n_normal}   attack windows: {n_attack}")
    print(f"  attack types  : {dict(atk_counts)}")
    if dens_vals:
        print(
            f"  packet_density: min={min(dens_vals):.1f} max={max(dens_vals):.1f} "
            f"mean={sum(dens_vals)/len(dens_vals):.1f} nunique={len(set(dens_vals))}"
        )


if __name__ == "__main__":
    main()
