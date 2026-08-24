#!/usr/bin/env python3
"""Event-level detection delay, FA/hour, and offline evidence-gate table.

Reads labeled raw CSVs (collector START/STOP → attack_type). Does not change
the on-device tree. Evidence-gate is a *report*: density-leaf alarms are kept
only if the same 100 ms bin has a deauth or probe flag (firmware win_* when
present, else CSV subtype strings).

Usage:
  python host/train/event_level_eval.py
  python host/train/event_level_eval.py data/raw/nids_dataset_20260818_234622.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_RAW, FIGURES_DIR, ensure_data_dirs  # noqa: E402

DEFAULT_CAPTURES = (
    os.path.join(DATA_RAW, "nids_dataset_20260818_234622.csv"),
    os.path.join(DATA_RAW, "nids_dataset_20260816_015654.csv"),
)
GAP_SEC = 2.0
WINDOW_SEC = 0.1
QUIET_WIN_PKTS = 50.0


def _to_float(val, default=None):
    try:
        if val is None or val == "":
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


def _parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _pred_int(row, key):
    v = _to_float(row.get(key), default=None)
    if v is None:
        return None
    return 1 if v > 0.5 else 0


def _subtype_flag(row):
    sub = (row.get("subtype") or "").strip()
    csv_deauth = sub in ("DEAUTH", "DISASSOC")
    csv_probe = sub.startswith("PROBE")
    fw_deauth = _to_float(row.get("win_deauth"), default=None)
    fw_probe = _to_float(row.get("win_probe"), default=None)
    deauth = (fw_deauth is not None and fw_deauth > 0) or csv_deauth
    probe = (fw_probe is not None and fw_probe > 0) or csv_probe
    return deauth or probe


def load_rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        ts = _parse_ts(r.get("timestamp"))
        if ts is None:
            continue
        r["_ts"] = ts
        out.append(r)
    out.sort(key=lambda x: x["_ts"])
    return out


def attack_events(rows, gap_sec=GAP_SEC):
    """Contiguous START/STOP slices: attack_type != NONE, split on gaps."""
    events = []
    cur = None
    for r in rows:
        atk = (r.get("attack_type") or "NONE").strip() or "NONE"
        if atk == "NONE":
            if cur is not None:
                events.append(cur)
                cur = None
            continue
        ts = r["_ts"]
        if cur is None:
            cur = {"attack_type": atk, "start": ts, "end": ts, "rows": [r]}
            continue
        dt = (ts - cur["end"]).total_seconds()
        if atk != cur["attack_type"] or dt > gap_sec:
            events.append(cur)
            cur = {"attack_type": atk, "start": ts, "end": ts, "rows": [r]}
        else:
            cur["end"] = ts
            cur["rows"].append(r)
    if cur is not None:
        events.append(cur)
    return events


def first_hit_delay(event, pred_key):
    t0 = event["start"]
    for r in event["rows"]:
        p = _pred_int(r, pred_key)
        if p == 1:
            return (r["_ts"] - t0).total_seconds()
    return None


def first_gated_delay(event, pred_key):
    t0 = event["start"]
    for r in event["rows"]:
        p = _pred_int(r, pred_key)
        if p == 1 and _subtype_flag(r):
            return (r["_ts"] - t0).total_seconds()
    return None


def bin_rows(rows, window_sec=WINDOW_SEC):
    bins = {}
    for r in rows:
        b = int(r["_ts"].timestamp() // window_sec)
        bins.setdefault(b, []).append(r)
    out = []
    for b in sorted(bins):
        group = bins[b]
        last = group[-1]
        atk_counts = Counter((r.get("attack_type") or "NONE").strip() or "NONE" for r in group)
        atk = atk_counts.most_common(1)[0][0]
        pkts = [_to_float(r.get("win_pkts"), default=None) for r in group]
        pkts = [x for x in pkts if x is not None]
        win_pkts = max(pkts) if pkts else float(len(group))
        fw_deauth = [_to_float(r.get("win_deauth"), default=None) for r in group]
        fw_probe = [_to_float(r.get("win_probe"), default=None) for r in group]
        fw_deauth = [x for x in fw_deauth if x is not None]
        fw_probe = [x for x in fw_probe if x is not None]
        csv_deauth = sum(
            1 for r in group
            if (r.get("subtype") or "").strip() in ("DEAUTH", "DISASSOC")
        )
        csv_probe = sum(
            1 for r in group
            if (r.get("subtype") or "").strip().startswith("PROBE")
        )
        deauth_n = max(fw_deauth) if fw_deauth else csv_deauth
        probe_n = max(fw_probe) if fw_probe else csv_probe
        mgmt = (deauth_n > 0) or (probe_n > 0)
        pred = _pred_int(last, "pred_attack")
        pred_raw = _pred_int(last, "pred_raw")
        out.append({
            "bin": b,
            "attack_type": atk,
            "win_pkts": win_pkts,
            "mgmt": mgmt,
            "pred": pred,
            "pred_raw": pred_raw,
            "gated": 1 if (pred == 1 and mgmt) else 0 if pred is not None else None,
            "gated_raw": 1 if (pred_raw == 1 and mgmt) else 0 if pred_raw is not None else None,
        })
    return out


def _rate(vals):
    nums = [v for v in vals if v is not None]
    if not nums:
        return None
    return sum(1 for v in nums if v > 0.5) / len(nums)


def fa_hour(windows, pred_key, quiet_only=False):
    if quiet_only:
        sel = [w for w in windows if w["attack_type"] == "NONE" and w["win_pkts"] < QUIET_WIN_PKTS]
    else:
        sel = [w for w in windows if w["attack_type"] == "NONE"]
    hours = len(sel) * WINDOW_SEC / 3600.0
    hits = sum(1 for w in sel if w.get(pred_key) == 1)
    edges = 0
    prev = 0
    for w in sel:
        cur = 1 if w.get(pred_key) == 1 else 0
        if cur and not prev:
            edges += 1
        prev = cur
    return {
        "n_windows": len(sel),
        "hours": hours,
        "alarms": hits,
        "rising_edges": edges,
        "fa_per_hour": (hits / hours) if hours > 0 else None,
        "fa_events_per_hour": (edges / hours) if hours > 0 else None,
        "window_rate": (hits / len(sel)) if sel else None,
    }


def slice_gate(windows, mask_fn, name):
    sel = [w for w in windows if mask_fn(w)]
    return {
        "slice": name,
        "n_windows": len(sel),
        "pred": _rate([w["pred"] for w in sel]),
        "pred_raw": _rate([w["pred_raw"] for w in sel]),
        "gated": _rate([w["gated"] for w in sel]),
        "gated_raw": _rate([w["gated_raw"] for w in sel]),
        "mgmt_frac": _rate([1 if w["mgmt"] else 0 for w in sel]),
        "density_only_raw_frac": _rate([
            1 if (w["pred_raw"] == 1 and not w["mgmt"]) else 0
            for w in sel if w["pred_raw"] is not None
        ]),
    }


def summarize_capture(path):
    rows = load_rows(path)
    cols = set(rows[0].keys()) if rows else set()
    has_pred_raw = any(_pred_int(r, "pred_raw") is not None for r in rows[:500])
    has_win_sub = any(
        r.get("win_deauth") not in (None, "") for r in rows[:200]
    ) if rows else False
    events = attack_events(rows)
    event_rows = []
    for i, ev in enumerate(events):
        dur = (ev["end"] - ev["start"]).total_seconds()
        d_pred = first_hit_delay(ev, "pred_attack")
        d_raw = first_hit_delay(ev, "pred_raw") if has_pred_raw else None
        d_g = first_gated_delay(ev, "pred_attack")
        event_rows.append({
            "i": i,
            "attack_type": ev["attack_type"],
            "duration_s": dur,
            "n_syslog": len(ev["rows"]),
            "detected_pred": d_pred is not None,
            "delay_pred_s": d_pred,
            "detected_pred_raw": d_raw is not None if has_pred_raw else None,
            "delay_pred_raw_s": d_raw,
            "detected_gated": d_g is not None,
            "delay_gated_s": d_g,
        })

    by_type = {}
    for atk in sorted({e["attack_type"] for e in event_rows}):
        sl = [e for e in event_rows if e["attack_type"] == atk]
        delays = [e["delay_pred_s"] for e in sl if e["delay_pred_s"] is not None]
        by_type[atk] = {
            "n_events": len(sl),
            "detected": sum(1 for e in sl if e["detected_pred"]),
            "detection_rate": (sum(1 for e in sl if e["detected_pred"]) / len(sl)) if sl else None,
            "delay_s_median": _median(delays),
            "delay_s_mean": (sum(delays) / len(delays)) if delays else None,
            "missed": [e["i"] for e in sl if not e["detected_pred"]],
            "gated_detected": sum(1 for e in sl if e["detected_gated"]),
            "gated_detection_rate": (
                sum(1 for e in sl if e["detected_gated"]) / len(sl)
            ) if sl else None,
        }

    windows = bin_rows(rows)
    fa = {
        "none_all": {
            "pred": fa_hour(windows, "pred", quiet_only=False),
            "pred_raw": fa_hour(windows, "pred_raw", quiet_only=False) if has_pred_raw else None,
            "gated": fa_hour(windows, "gated", quiet_only=False),
        },
        "none_quiet_win_pkts_lt_50": {
            "pred": fa_hour(windows, "pred", quiet_only=True),
            "pred_raw": fa_hour(windows, "pred_raw", quiet_only=True) if has_pred_raw else None,
            "gated": fa_hour(windows, "gated", quiet_only=True),
        },
    }
    gate_table = [
        slice_gate(windows, lambda w: w["attack_type"] == "NONE" and w["win_pkts"] < QUIET_WIN_PKTS, "NONE quiet"),
        slice_gate(windows, lambda w: w["attack_type"] == "NONE" and w["win_pkts"] >= QUIET_WIN_PKTS, "NONE busy"),
        slice_gate(windows, lambda w: w["attack_type"] == "NONE", "NONE all"),
    ]
    for name in sorted({w["attack_type"] for w in windows if w["attack_type"] != "NONE"}):
        gate_table.append(slice_gate(windows, lambda w, n=name: w["attack_type"] == n, name))

    t0 = rows[0]["_ts"] if rows else None
    t1 = rows[-1]["_ts"] if rows else None
    return {
        "path": os.path.basename(path),
        "n_syslog": len(rows),
        "span_s": (t1 - t0).total_seconds() if t0 and t1 else 0.0,
        "has_pred_raw": has_pred_raw,
        "has_win_subtype": has_win_sub,
        "columns_note": (
            "pred_raw missing" if not has_pred_raw else "pred_raw present"
        ) + ("; firmware win_deauth/probe" if has_win_sub else "; subtype flag from CSV strings"),
        "events": event_rows,
        "by_attack": by_type,
        "fa_per_hour": fa,
        "evidence_gate": {
            "rule": "keep pred only if same 100 ms bin has deauth or probe flag; table only, board tree unchanged",
            "slices": gate_table,
        },
        "header_has_pred_raw_col": "pred_raw" in cols,
    }


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
    return f"{100.0 * x:.1f}%"


def _fmt_num(x, digits=2):
    if x is None:
        return "-"
    return f"{x:.{digits}f}"


def print_capture(rep):
    print(f"\n=== {rep['path']} ===")
    print(f"  syslog={rep['n_syslog']} span={rep['span_s']:.1f}s  {rep['columns_note']}")
    print("  events:")
    for atk, st in rep["by_attack"].items():
        print(
            f"    {atk}: {st['detected']}/{st['n_events']} detected  "
            f"rate={_fmt_rate(st['detection_rate'])}  "
            f"delay med={_fmt_num(st['delay_s_median'])}s  "
            f"gated={st['gated_detected']}/{st['n_events']}"
        )
    print("  FA/hour (NONE windows, last syslog in 100 ms bin):")
    for slice_name, block in rep["fa_per_hour"].items():
        pred = block["pred"]
        print(
            f"    {slice_name} pred: alarms={pred['alarms']} edges={pred['rising_edges']} "
            f"hours={_fmt_num(pred['hours'], 3)}  "
            f"FA/h(win)={_fmt_num(pred['fa_per_hour'], 1)}  "
            f"FA/h(evt)={_fmt_num(pred['fa_events_per_hour'], 1)}  "
            f"win%={_fmt_rate(pred['window_rate'])}"
        )
        raw = block.get("pred_raw")
        if raw:
            print(
                f"    {slice_name} pred_raw: alarms={raw['alarms']} edges={raw['rising_edges']}  "
                f"FA/h(win)={_fmt_num(raw['fa_per_hour'], 1)}  "
                f"FA/h(evt)={_fmt_num(raw['fa_events_per_hour'], 1)}  "
                f"win%={_fmt_rate(raw['window_rate'])}"
            )
        gated = block["gated"]
        print(
            f"    {slice_name} evidence-gated: alarms={gated['alarms']} edges={gated['rising_edges']}  "
            f"FA/h(win)={_fmt_num(gated['fa_per_hour'], 1)}  "
            f"FA/h(evt)={_fmt_num(gated['fa_events_per_hour'], 1)}  "
            f"win%={_fmt_rate(gated['window_rate'])}"
        )
    print("  evidence-gate table (window last-sample):")
    print(f"    {'slice':<16} {'n':>6} {'pred':>8} {'raw':>8} {'gated':>8} {'g-raw':>8} {'mgmt':>8} {'dens-only':>10}")
    for s in rep["evidence_gate"]["slices"]:
        print(
            f"    {s['slice']:<16} {s['n_windows']:>6} "
            f"{_fmt_rate(s['pred']):>8} {_fmt_rate(s['pred_raw']):>8} "
            f"{_fmt_rate(s['gated']):>8} {_fmt_rate(s['gated_raw']):>8} "
            f"{_fmt_rate(s['mgmt_frac']):>8} {_fmt_rate(s['density_only_raw_frac']):>10}"
        )


def to_markdown(reports):
    lines = [
        "# Event-level eval on existing labeled captures",
        "",
        "> Private. Date: 2026-08-24.  ",
        "> Script: `host/train/event_level_eval.py`. Board tree **unchanged**.  ",
        "> Delay = seconds from START (`attack_type` leaves NONE) to first `pred_attack=1`.  ",
        "> FA/hour uses last syslog in each 100 ms bin. Quiet = NONE and `win_pkts` < 50.  ",
        "> Evidence-gate is offline only: keep an alarm iff the same bin has deauth or probe.",
        "",
        "These captures **predate** firmware `win_deauth/probe/beacon/auth`; subtype flags",
        "here are CSV strings (thinned). After the 15 min contract smoke, re-run this script.",
        "",
    ]
    for rep in reports:
        lines.append(f"## {rep['path']}")
        lines.append("")
        lines.append(f"- syslog rows: {rep['n_syslog']}; span {rep['span_s']:.1f}s")
        lines.append(f"- {rep['columns_note']}")
        lines.append("")
        lines.append("| attack | events | detected | rate | delay med (s) | gated detected |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for atk, st in rep["by_attack"].items():
            lines.append(
                f"| {atk} | {st['n_events']} | {st['detected']} | "
                f"{_fmt_rate(st['detection_rate'])} | {_fmt_num(st['delay_s_median'])} | "
                f"{st['gated_detected']}/{st['n_events']} |"
            )
        lines.append("")
        lines.append("| NONE slice | pred win% | pred FA/h win | pred FA/h evt | pred_raw FA/h evt | gated FA/h evt |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for slice_name, block in rep["fa_per_hour"].items():
            raw = block.get("pred_raw") or {}
            lines.append(
                f"| {slice_name} | {_fmt_rate(block['pred']['window_rate'])} | "
                f"{_fmt_num(block['pred']['fa_per_hour'], 1)} | "
                f"{_fmt_num(block['pred']['fa_events_per_hour'], 1)} | "
                f"{_fmt_num(raw.get('fa_events_per_hour'), 1)} | "
                f"{_fmt_num(block['gated']['fa_events_per_hour'], 1)} |"
            )
        lines.append("")
        lines.append("Evidence-gate (same 100 ms bin; **not** flashed):")
        lines.append("")
        lines.append("| slice | n | pred | pred_raw | gated | gated_raw | mgmt flag | density-only raw |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        for s in rep["evidence_gate"]["slices"]:
            lines.append(
                f"| {s['slice']} | {s['n_windows']} | {_fmt_rate(s['pred'])} | "
                f"{_fmt_rate(s['pred_raw'])} | {_fmt_rate(s['gated'])} | "
                f"{_fmt_rate(s['gated_raw'])} | {_fmt_rate(s['mgmt_frac'])} | "
                f"{_fmt_rate(s['density_only_raw_frac'])} |"
            )
        lines.append("")
    lines.extend([
        "## How to read this",
        "",
        "- Detection rate / delay answer paper-style **event** metrics, not window F1.",
        "- A long SYN flood can still count as detected if any window lights; window rate stays low (see leftover 1-3).",
        "- Quiet FA/hour **windows** = (pred=1 bins) / hours; at 10 Hz that inflates flicker.",
        "  **events** = rising edges (light turns on). Prefer events for the appendix.",
        "- Quiet FA/hour is the deploy number; busy NONE on 234622 is unlabeled hping, not dorm video.",
        "- Gated columns show what a deauth/probe-flag-before-density-leaf rule would do **offline**.",
        "  SYN and busy density alarms drop; deauth/probe events should stay if CSV subtype survived thinning.",
        "- Do not flash a new tree from this table.",
        "",
    ])
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Event-level delay / FA-hour / evidence-gate")
    ap.add_argument("inputs", nargs="*", help="raw nids_dataset_*.csv (default: 234622 + 015654)")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--md-out", default=None)
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

    json_out = args.json_out or os.path.join(FIGURES_DIR, "event_level_old_csv_20260824.json")
    os.makedirs(os.path.dirname(json_out) or ".", exist_ok=True)
    with open(json_out, "w", encoding="utf-8") as fh:
        json.dump(reports, fh, indent=2, default=str)
    print(f"\nWrote {json_out}")

    md_out = args.md_out or os.path.join(
        _ROOT, "note", "private", "eval", "event_level_old_csv_20260824.md"
    )
    os.makedirs(os.path.dirname(md_out), exist_ok=True)
    with open(md_out, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(reports))
    print(f"Wrote {md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
