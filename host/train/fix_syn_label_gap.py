#!/usr/bin/env python3
"""
One-shot fix for Phase A capture where SYN STOP was missed:
the intended NORMAL gap before ARP stayed labeled as SYN_FLOOD.

Keeps the first `keep_sec` of the (only/long) SYN_FLOOD run as attack;
relabels the remainder of that run to NORMAL/NONE.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--keep-sec", type=float, default=130.0,
                    help="Seconds of SYN_FLOOD to keep from the start of that run")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.out) if args.out else inp.with_name(inp.stem + "_fixed.csv")

    with inp.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
        fieldnames = list(rows[0].keys()) if rows else []

    syn_start = None
    fixed = 0
    for r in rows:
        if r.get("attack_type") != "SYN_FLOOD" or str(r.get("label")) != "1":
            continue
        try:
            t = datetime.fromisoformat(r["timestamp"])
        except (KeyError, ValueError):
            continue
        if syn_start is None:
            syn_start = t
        elapsed = (t - syn_start).total_seconds()
        if elapsed > args.keep_sec:
            r["label"] = "0"
            r["attack_type"] = "NONE"
            fixed += 1

    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Relabeled {fixed} rows after first {args.keep_sec}s of SYN_FLOOD -> NORMAL")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
