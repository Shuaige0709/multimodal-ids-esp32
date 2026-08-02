#!/usr/bin/env python3
"""
Phase A acceptance gate: check that a window CSV is balanced enough for paper metrics.

Usage:
  python host/train/check_dataset_balance.py
  python host/train/check_dataset_balance.py data/windows/nids_windows_....csv
  python host/train/check_dataset_balance.py --strict   # exit 1 if gates fail
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_WINDOWS, FIGURES_DIR, ensure_data_dirs  # noqa: E402
from host.train.nids_features import (  # noqa: E402
    ATTACK_TYPE_COL,
    LABEL_COL,
    MIN_NORMAL_WINDOWS,
    MIN_WINDOWS_PER_ATTACK,
    REQUIRED_ATTACK_TYPES,
)


def find_default():
    ensure_data_dirs()
    hits = sorted(glob.glob(os.path.join(DATA_WINDOWS, "nids_windows_*.csv")))
    if not hits:
        raise SystemExit(f"No windows CSV in {DATA_WINDOWS}. Run aggregate_windows.py first.")
    return hits[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", nargs="?", default=None)
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero if Phase A gates fail")
    ap.add_argument("--min-normal", type=int, default=MIN_NORMAL_WINDOWS)
    ap.add_argument("--min-per-attack", type=int, default=MIN_WINDOWS_PER_ATTACK)
    args = ap.parse_args()

    import pandas as pd

    path = args.dataset or find_default()
    df = pd.read_csv(path)
    df[LABEL_COL] = (pd.to_numeric(df[LABEL_COL], errors="coerce").fillna(0) > 0).astype(int)
    if ATTACK_TYPE_COL not in df.columns:
        df[ATTACK_TYPE_COL] = "NONE"

    n_normal = int((df[LABEL_COL] == 0).sum())
    n_attack = int((df[LABEL_COL] == 1).sum())
    atk = Counter(df.loc[df[LABEL_COL] == 1, ATTACK_TYPE_COL].astype(str))

    report = {
        "dataset": os.path.basename(path),
        "n_windows": len(df),
        "n_normal": n_normal,
        "n_attack": n_attack,
        "attack_type_counts": dict(atk),
        "ratio_attack_over_normal": (n_attack / n_normal) if n_normal else None,
        "gates": {},
        "pass": True,
        "notes": [],
    }

    def gate(name, ok, detail):
        report["gates"][name] = {"ok": bool(ok), "detail": detail}
        if not ok:
            report["pass"] = False

    gate("normal_count", n_normal >= args.min_normal,
         f"normal={n_normal} (need >={args.min_normal})")
    for t in REQUIRED_ATTACK_TYPES:
        c = int(atk.get(t, 0))
        gate(f"attack_{t}", c >= args.min_per_attack,
             f"{t}={c} (need >={args.min_per_attack})")
    if n_normal > 0:
        ratio = n_attack / n_normal
        gate("not_syn_dominated_ratio",
             ratio <= 8.0,
             f"attack/normal={ratio:.2f} (want <=8; old SYN-heavy sets fail)")
    else:
        gate("not_syn_dominated_ratio", False, "no NORMAL windows")

    syn = int(atk.get("SYN_FLOOD", 0))
    if n_attack > 0:
        gate("syn_share",
             (syn / n_attack) <= 0.70,
             f"SYN share={syn / n_attack:.2%} of attacks (want <=70%)")

    print(f"Dataset: {path}")
    print(f"  windows={len(df)}  normal={n_normal}  attack={n_attack}")
    print(f"  types={dict(atk)}")
    for name, g in report["gates"].items():
        mark = "PASS" if g["ok"] else "FAIL"
        print(f"  [{mark}] {name}: {g['detail']}")

    if report["pass"]:
        print("\nPhase A balance gates: PASS - safe to train paper metrics.")
        report["notes"].append("Re-flash model.h after analyze_and_train.py.")
    else:
        print("\nPhase A balance gates: FAIL - re-collect with Mode P/S:")
        print("  NORMAL + DEAUTH + SYN_FLOOD + ARP_SPOOF (equal duration), HIPS off.")
        print("  See note/lab_runbook.md (and note/private/phase_a_collection.md if you keep a personal checklist)")

    out = os.path.join(FIGURES_DIR, "phase_a_balance_report.json")
    os.makedirs(FIGURES_DIR, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"Wrote {out}")

    if args.strict and not report["pass"]:
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
