#!/usr/bin/env python3
"""
Calibration A — offline IDLE baseline vs absolute nids-counts density leaf.

Compares:
  * absolute: approximate deployed tree density path (deauth==0 & tot>27.5 → attack)
  * relative: per-capture IDLE calib → attack if deauth>0.5 OR tot > k * IDLE_p90

Usage:
  python host/train/idle_baseline_calib_eval.py
  python host/train/idle_baseline_calib_eval.py --k 1.5 --calib-frac 0.3
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import FIGURES_DIR, ensure_data_dirs  # noqa: E402

# Leaf from main/model.h nids-counts (Generated 2026-08-09T15:05:44)
ABS_TOT_THR = 27.5

DEFAULT_DATASETS = [
    ("matched_20260809", "data/windows/nids_windows_20260809_000851.csv"),
    ("quiet_auth_try_002829", "data/windows/nids_windows_20260810_002829.csv"),
    ("busy_auth_try_221217", "data/windows/nids_windows_20260810_221217.csv"),
]


def _abs_pred(deauth: np.ndarray, tot: np.ndarray) -> np.ndarray:
    """Coarse stand-in for nids-counts: deauth path OR density leaf."""
    return ((deauth > 0.5) | (tot > ABS_TOT_THR)).astype(int)


def _rel_pred(
    deauth: np.ndarray, tot: np.ndarray, baseline_p90: float, k: float
) -> np.ndarray:
    thr = max(baseline_p90 * k, 1.0)
    return ((deauth > 0.5) | (tot > thr)).astype(int)


def _fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    mask = y_true == 0
    if not mask.any():
        return float("nan")
    return float((y_pred[mask] == 1).mean())


def _recall_attack(atypes: np.ndarray, y_pred: np.ndarray, name: str) -> float | None:
    mask = atypes == name
    if not mask.any():
        return None
    return float((y_pred[mask] == 1).mean())


def eval_one(path: str, label: str, k: float, calib_frac: float) -> dict:
    df = pd.read_csv(path)
    at = df["attack_type"].astype(str).to_numpy()
    y = df["label"].astype(int).to_numpy()
    deauth = df["deauth_packets"].to_numpy(dtype=float)
    tot = df["total_packets"].to_numpy(dtype=float)

    idle = df[df["attack_type"] == "NONE"]
    idle_tot = idle["total_packets"].to_numpy(dtype=float)
    n_calib = max(1, int(len(idle_tot) * calib_frac))
    # chronological: windows file is time-ordered from aggregate
    calib = idle_tot[:n_calib]
    hold_idle = idle.iloc[n_calib:]
    p90 = float(np.quantile(calib, 0.90)) if len(calib) else 0.0
    p50 = float(np.median(calib)) if len(calib) else 0.0

    abs_all = _abs_pred(deauth, tot)
    rel_all = _rel_pred(deauth, tot, p90, k)

    # FPR on held-out IDLE only (fairer for relative)
    if len(hold_idle):
        hd = hold_idle["deauth_packets"].to_numpy(dtype=float)
        ht = hold_idle["total_packets"].to_numpy(dtype=float)
        hy = np.zeros(len(hold_idle), dtype=int)
        abs_fpr_hold = _fpr(hy, _abs_pred(hd, ht))
        rel_fpr_hold = _fpr(hy, _rel_pred(hd, ht, p90, k))
    else:
        abs_fpr_hold = rel_fpr_hold = float("nan")

    out = {
        "label": label,
        "path": path,
        "n_windows": int(len(df)),
        "idle_stats": {
            "n": int(len(idle)),
            "tot_mean": float(idle_tot.mean()) if len(idle_tot) else None,
            "tot_p90_all": float(np.quantile(idle_tot, 0.90)) if len(idle_tot) else None,
            "calib_n": int(n_calib),
            "calib_p50": p50,
            "calib_p90": p90,
            "rel_threshold": float(max(p90 * k, 1.0)),
        },
        "absolute": {
            "thr_tot": ABS_TOT_THR,
            "fpr_all_none": _fpr(y, abs_all),
            "fpr_holdout_none": abs_fpr_hold,
            "deauth_recall": _recall_attack(at, abs_all, "DEAUTH"),
            "auth_flood_rate": _recall_attack(at, abs_all, "AUTH_FLOOD"),
            "syn_recall": _recall_attack(at, abs_all, "SYN_FLOOD"),
            "arp_recall": _recall_attack(at, abs_all, "ARP_SPOOF"),
        },
        "relative_k": {
            "k": k,
            "fpr_all_none": _fpr(y, rel_all),
            "fpr_holdout_none": rel_fpr_hold,
            "deauth_recall": _recall_attack(at, rel_all, "DEAUTH"),
            "auth_flood_rate": _recall_attack(at, rel_all, "AUTH_FLOOD"),
            "syn_recall": _recall_attack(at, rel_all, "SYN_FLOOD"),
            "arp_recall": _recall_attack(at, rel_all, "ARP_SPOOF"),
        },
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k", type=float, default=2.0, help="tot > k * IDLE_calib_p90")
    ap.add_argument(
        "--calib-frac",
        type=float,
        default=0.3,
        help="fraction of IDLE windows used for baseline (time-ordered)",
    )
    ap.add_argument(
        "--json-out",
        default=None,
        help="default: docs/figures/idle_baseline_calib_YYYYMMDD.json",
    )
    args = ap.parse_args()

    ensure_data_dirs()
    results = []
    for label, rel in DEFAULT_DATASETS:
        path = os.path.join(_ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            print(f"[skip] missing {path}")
            continue
        results.append(eval_one(path, label, args.k, args.calib_frac))

    print(f"Calibration A offline  |  k={args.k}  calib_frac={args.calib_frac}")
    print(f"Absolute density leaf: total_packets > {ABS_TOT_THR} (or deauth>0)\n")
    for r in results:
        print(f"=== {r['label']} ===")
        s = r["idle_stats"]
        print(
            f"  IDLE n={s['n']} tot_mean={s['tot_mean']:.1f} "
            f"calib_p90={s['calib_p90']:.1f} → rel_thr={s['rel_threshold']:.1f}"
        )
        a, b = r["absolute"], r["relative_k"]
        print(
            f"  ABS  FPR_hold={a['fpr_holdout_none']:.3f}  "
            f"DEAUTH={a['deauth_recall']}  AUTH={a['auth_flood_rate']}"
        )
        print(
            f"  REL  FPR_hold={b['fpr_holdout_none']:.3f}  "
            f"DEAUTH={b['deauth_recall']}  AUTH={b['auth_flood_rate']}"
        )
        print()

    out = {
        "k": args.k,
        "calib_frac": args.calib_frac,
        "absolute_tot_thr": ABS_TOT_THR,
        "note": (
            "Offline stand-in for nids-counts density leaf vs per-capture IDLE p90*k. "
            "Not exported to MCU. September: reopen Phase C on fixed AP."
        ),
        "datasets": results,
    }
    json_path = args.json_out or os.path.join(
        FIGURES_DIR, "idle_baseline_calib_20260810.json"
    )
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"Wrote {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
