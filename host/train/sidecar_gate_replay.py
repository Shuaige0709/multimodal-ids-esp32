#!/usr/bin/env python3
"""Offline sidecar / hybrid-gate replay. Does not flash or retrain.

Compares, on the same 100 ms bins:
  pred_raw, pred_attack (board lamp), offline evidence-gate, twin/rogue,
  win_auth, per-window gw_mac change (NOT cumulative gw_flip), 2-of-5 hysteresis.

Usage:
  python host/train/sidecar_gate_replay.py
  python host/train/sidecar_gate_replay.py data/raw/nids_dataset_XXXX.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, deque
from datetime import timedelta

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_RAW, ensure_data_dirs  # noqa: E402

from host.train.event_level_eval import (  # noqa: E402
    GAP_SEC,
    WINDOW_SEC,
    _pred_int,
    _to_float,
    attack_events,
    load_rows,
)

DEFAULT_CAPTURES = (
    os.path.join(DATA_RAW, "nids_dataset_20260827_010524.csv"),
    os.path.join(DATA_RAW, "nids_dataset_20260826_232220.csv"),
    os.path.join(DATA_RAW, "nids_dataset_20260828_015543.csv"),
    os.path.join(DATA_RAW, "nids_dataset_20260830_233008.csv"),
    os.path.join(DATA_RAW, "nids_dataset_20260818_234622.csv"),
)

HYST_N = 2
HYST_M = 5
MIN_HOURS_FOR_FAH = 0.25  # 15 min; shorter → report edges only


def _mac_ok(mac):
    s = (mac or "").strip()
    if not s or s == "-":
        return None
    return s.lower()


def _mgmt_flag(row):
    sub = (row.get("subtype") or "").strip()
    csv_deauth = sub in ("DEAUTH", "DISASSOC")
    csv_probe = sub.startswith("PROBE")
    fw_deauth = _to_float(row.get("win_deauth"), default=None)
    fw_probe = _to_float(row.get("win_probe"), default=None)
    deauth = (fw_deauth is not None and fw_deauth > 0) or csv_deauth
    probe = (fw_probe is not None and fw_probe > 0) or csv_probe
    return deauth, probe, deauth or probe


def bin_windows(rows, window_sec=WINDOW_SEC):
    bins = {}
    for r in rows:
        b = int(r["_ts"].timestamp() // window_sec)
        bins.setdefault(b, []).append(r)
    out = []
    prev_mac = None
    for b in sorted(bins):
        group = bins[b]
        last = group[-1]
        atk_counts = Counter(
            (r.get("attack_type") or "NONE").strip() or "NONE" for r in group
        )
        atk = atk_counts.most_common(1)[0][0]
        deauth_n, probe_n, mgmt = False, False, False
        any_deauth = False
        any_probe = False
        for r in group:
            d, p, m = _mgmt_flag(r)
            any_deauth = any_deauth or d
            any_probe = any_probe or p
            mgmt = mgmt or m
        deauth_n, probe_n = any_deauth, any_probe

        twin_vals = [_to_float(r.get("win_twin"), default=None) for r in group]
        rogue_vals = [_to_float(r.get("win_rogue"), default=None) for r in group]
        auth_vals = [_to_float(r.get("win_auth"), default=None) for r in group]
        twin_vals = [x for x in twin_vals if x is not None]
        rogue_vals = [x for x in rogue_vals if x is not None]
        auth_vals = [x for x in auth_vals if x is not None]
        has_twin_col = any(
            r.get("win_twin") not in (None, "") for r in group
        )
        has_auth_col = any(
            r.get("win_auth") not in (None, "") for r in group
        )

        macs = [_mac_ok(r.get("gw_mac")) for r in group]
        macs = [m for m in macs if m]
        cur_mac = macs[-1] if macs else _mac_ok(last.get("gw_mac"))
        gw_changed = (
            prev_mac is not None
            and cur_mac is not None
            and cur_mac != prev_mac
        )
        if cur_mac is not None:
            prev_mac = cur_mac

        pred = _pred_int(last, "pred_attack")
        pred_raw = _pred_int(last, "pred_raw")
        twin_hit = 1 if (any(x >= 1 for x in twin_vals) or any(x >= 1 for x in rogue_vals)) else 0
        auth_hit = 1 if any(x >= 1 for x in auth_vals) else 0
        ev_offline = 1 if (pred_raw == 1 and mgmt) else 0 if pred_raw is not None else None

        out.append({
            "bin": b,
            "ts": last["_ts"],
            "attack_type": atk,
            "pred": pred,
            "pred_raw": pred_raw,
            "mgmt": 1 if mgmt else 0,
            "deauth": 1 if deauth_n else 0,
            "probe": 1 if probe_n else 0,
            "ev_offline": ev_offline,
            "twin_hit": twin_hit if has_twin_col else None,
            "auth_hit": auth_hit if has_auth_col else None,
            "gw_changed": 1 if gw_changed else 0,
            "has_twin_col": has_twin_col,
            "has_auth_col": has_auth_col,
        })
    return out


def hysteresis(flags, n=HYST_N, m=HYST_M):
    """flags: iterable of 0/1/None. None treated as 0."""
    buf = deque(maxlen=m)
    out = []
    for f in flags:
        v = 1 if f == 1 else 0
        buf.append(v)
        out.append(1 if sum(buf) >= n else 0)
    return out


def _as_flag(w, key):
    v = w.get(key)
    if v is None:
        return None
    return 1 if v == 1 else 0


def attach_policies(windows):
    raw = [_as_flag(w, "pred_raw") for w in windows]
    board = [_as_flag(w, "pred") for w in windows]
    ev = [_as_flag(w, "ev_offline") for w in windows]
    twin = [_as_flag(w, "twin_hit") for w in windows]
    auth = [_as_flag(w, "auth_hit") for w in windows]
    gw = [_as_flag(w, "gw_changed") for w in windows]

    twin_and_raw = []
    auth_and_raw = []
    layer1 = []
    cascaded = []
    for w, r in zip(windows, raw):
        t = w.get("twin_hit")
        a = w.get("auth_hit")
        g = w.get("gw_changed") or 0
        twin_and_raw.append(
            1 if (r == 1 and t == 1) else 0 if r is not None and t is not None else None
        )
        auth_and_raw.append(
            1 if (r == 1 and a == 1) else 0 if r is not None and a is not None else None
        )
        l1_parts = [w.get("mgmt") or 0]
        if t is not None:
            l1_parts.append(t)
        if a is not None:
            l1_parts.append(a)
        l1_parts.append(g)
        l1 = 1 if any(x == 1 for x in l1_parts) else 0
        layer1.append(l1)
        cascaded.append(1 if (l1 == 1 and r == 1) else 0 if r is not None else None)

    hyst_board = hysteresis(board)
    hyst_ev = hysteresis(ev)

    policies = {
        "pred_raw": raw,
        "pred_attack": board,
        "ev_gate_offline": ev,
        "twin_hit": twin,
        "twin_and_raw": twin_and_raw,
        "auth_hit": auth,
        "auth_and_raw": auth_and_raw,
        "gw_mac_changed": gw,
        "layer1_any": layer1,
        "cascaded_l1_and_raw": cascaded,
        f"hyst_{HYST_N}of{HYST_M}_board": hyst_board,
        f"hyst_{HYST_N}of{HYST_M}_ev": hyst_ev,
    }
    for name, flags in policies.items():
        for w, f in zip(windows, flags):
            w[name] = f
    return policies


def rising_edges(flags):
    n = 0
    prev = 0
    for f in flags:
        cur = 1 if f == 1 else 0
        if cur and not prev:
            n += 1
        prev = cur
    return n


def first_policy_delay(event, windows, policy, gap_before_s=0.05):
    t0 = event["start"]
    t1 = event["end"]
    for w in windows:
        if w["ts"] < t0 - timedelta(seconds=gap_before_s):
            continue
        if w["ts"] > t1:
            break
        if w.get(policy) == 1:
            return (w["ts"] - t0).total_seconds()
    return None


def none_stats(windows, policy):
    sel = [w for w in windows if w["attack_type"] == "NONE"]
    flags = [w.get(policy) for w in sel]
    present = any(f is not None for f in flags)
    if not present:
        return None
    hours = len(sel) * WINDOW_SEC / 3600.0
    edges = rising_edges(flags)
    hits = sum(1 for f in flags if f == 1)
    fa_h = (edges / hours) if hours >= MIN_HOURS_FOR_FAH and hours > 0 else None
    return {
        "n_windows": len(sel),
        "hours": hours,
        "hits": hits,
        "rising_edges": edges,
        "fa_events_per_hour": fa_h,
    }


def event_stats(events, windows, policy):
    present = any(w.get(policy) is not None for w in windows)
    by = {}
    for ev in events:
        atk = ev["attack_type"]
        by.setdefault(atk, []).append(ev)
    out = {}
    for atk, evs in sorted(by.items()):
        if not present:
            out[atk] = {
                "n": len(evs),
                "detected": None,
                "rate": None,
                "delay_med_s": None,
                "available": False,
            }
            continue
        delays = []
        detected = 0
        for ev in evs:
            d = first_policy_delay(ev, windows, policy)
            if d is not None:
                detected += 1
                delays.append(d)
        out[atk] = {
            "n": len(evs),
            "detected": detected,
            "rate": (detected / len(evs)) if evs else None,
            "delay_med_s": _median(delays),
            "available": True,
        }
    return out


def _median(vals):
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    if n % 2:
        return s[n // 2]
    return 0.5 * (s[n // 2 - 1] + s[n // 2])


def _fmt_rate(x):
    if x is None:
        return "-"
    return f"{100.0 * x:.0f}%"


def _fmt_num(x, digits=2):
    if x is None:
        return "-"
    return f"{x:.{digits}f}"


def summarize_capture(path):
    rows = load_rows(path)
    if not rows:
        return {"path": os.path.basename(path), "empty": True}
    windows = bin_windows(rows)
    policies = attach_policies(windows)
    events = attack_events(rows, gap_sec=GAP_SEC)
    t0 = rows[0]["_ts"]
    t1 = rows[-1]["_ts"]
    cols = set(rows[0].keys())
    policy_block = {}
    for name in policies:
        policy_block[name] = {
            "none": none_stats(windows, name),
            "events": event_stats(events, windows, name),
        }
    return {
        "path": os.path.basename(path),
        "n_syslog": len(rows),
        "n_windows": len(windows),
        "span_s": (t1 - t0).total_seconds(),
        "has_pred_raw": "pred_raw" in cols,
        "has_twin": "win_twin" in cols,
        "has_auth": "win_auth" in cols,
        "attack_types": sorted({e["attack_type"] for e in events}),
        "n_events": len(events),
        "policies": policy_block,
    }


def print_capture(rep):
    if rep.get("empty"):
        print(f"\n=== {rep['path']} empty ===")
        return
    print(f"\n=== {rep['path']} ===")
    print(
        f"  syslog={rep['n_syslog']} windows={rep['n_windows']} "
        f"span={rep['span_s']:.1f}s  pred_raw={rep['has_pred_raw']} "
        f"twin={rep['has_twin']} auth={rep['has_auth']}"
    )
    attacks = rep["attack_types"]
    print(
        f"  {'policy':<28} {'NONE edge':>10} {'hrs':>7} {'FA/h':>8}  "
        + "  ".join(f"{a[:12]:>12}" for a in attacks)
    )
    for name, block in rep["policies"].items():
        none = block["none"]
        if none is None:
            none_s = f"{'n/a':>10} {'-':>7} {'-':>8}"
        else:
            fah = _fmt_num(none["fa_events_per_hour"], 1)
            none_s = (
                f"{none['rising_edges']:>10} {_fmt_num(none['hours'], 3):>7} {fah:>8}"
            )
        parts = [f"  {name:<28} {none_s}"]
        for a in attacks:
            st = block["events"].get(a) or {}
            n = st.get("n")
            if n is None or st.get("available") is False or st.get("detected") is None:
                parts.append(f"{'n/a':>12}")
            else:
                delay = _fmt_num(st.get("delay_med_s"))
                parts.append(f"{st['detected']}/{n} {delay}s".rjust(12))
        print("  ".join(parts))
    print(
        "  note: FA/h only if NONE hours >= "
        f"{MIN_HOURS_FOR_FAH:.2f}; else '-' (count edges only)."
    )
    print(
        "  gw_mac_changed is per-window MAC edge, not cumulative gw_flip. "
        "twin/auth '-' columns mean the CSV has no field."
    )


def main():
    ap = argparse.ArgumentParser(description="Offline sidecar / hybrid-gate replay")
    ap.add_argument("inputs", nargs="*", help="raw nids_dataset_*.csv")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()
    ensure_data_dirs()
    inputs = args.inputs or list(DEFAULT_CAPTURES)
    reports = []
    for path in inputs:
        if not os.path.isfile(path):
            print(f"  skip missing {path}")
            continue
        reports.append(summarize_capture(path))
        print_capture(reports[-1])
    if not reports:
        raise SystemExit("No captures evaluated.")
    json_out = args.json_out
    if json_out:
        os.makedirs(os.path.dirname(json_out) or ".", exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(reports, fh, indent=2, default=str)
        print(f"\nWrote {json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
