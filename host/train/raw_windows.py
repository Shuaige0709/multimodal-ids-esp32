"""Read closed raw SQLite archives -> versioned window JSONL (streaming packet rows).

Run: python -m host.train.raw_windows captures/run_001 --out data/raw_windows_v1
Original archives are read-only. Output directory must not already exist.
"""
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import statistics
import sys

from host.collector.raw_labels import normalize_label
from host.train.raw_features import SCHEMA, WIRELESS, HARDWARE, parse_header


def database_path(path):
    path = Path(path)
    return path / "dataset.sqlite3" if path.is_dir() else path


def mean(values):
    return statistics.fmean(values) if values else None


def label_for_interval(baseline, events, lo, hi, guard_ns):
    label = normalize_label(baseline)
    for when, value in events:
        if lo - guard_ns <= when <= hi + guard_ns:
            return None, True
        if when < lo:
            label = value
    return label, False


def features(packets, status):
    out = dict.fromkeys(WIRELESS + HARDWARE, None)
    counts = Counter()
    transmitters, bssids = set(), set()
    lengths, rssis, snrs, times = [], [], [], []
    for p in packets:
        lengths.append(p["original_len"])
        times.append(p["device_us"])
        if -127 <= p["rssi"] <= 0:
            rssis.append(p["rssi"])
            if -127 <= p["noise_floor"] < 0:
                snrs.append(p["rssi"] - p["noise_floor"])
        h = parse_header(p["payload"]) if not p["flags"] and not p["rx_state"] else None
        # SDK packet type: MGMT=0, CTRL=1, DATA=2, MISC=3.
        if h is None or h["kind"] != p["pkt_type"]:
            counts["invalid_headers"] += 1
            continue
        counts[("mgmt_count", "ctrl_count", "data_count")[h["kind"]]] += 1
        counts["retry"] += h["retry"]
        counts["protected"] += h["protected"]
        if h["ta"] is not None:
            transmitters.add(h["ta"])
        if h["bssid"] is not None:
            bssids.add(h["bssid"])
        if h["kind"] == 0:
            name = {8: "beacon_count", 12: "deauth_count", 10: "disassoc_count",
                    4: "probe_count", 5: "probe_count", 11: "auth_count"}.get(h["subtype"])
            if name:
                counts[name] += 1
    for name in WIRELESS:
        if name.endswith("_count"):
            out[name] = counts[name]
    n = len(packets)
    out.update(packet_count=n, retry_ratio=counts["retry"] / n if n else 0,
               protected_ratio=counts["protected"] / n if n else 0,
               unique_transmitters=len(transmitters), unique_bssids=len(bssids),
               frame_bytes=sum(lengths), length_mean=mean(lengths),
               length_max=max(lengths) if lengths else None,
               rssi_mean=mean(rssis), rssi_std=statistics.pstdev(rssis) if rssis else None,
               snr_mean=mean(snrs), iat_mean_us=mean([b-a for a, b in zip(times, times[1:])]))
    if status is not None:
        out.update(heap=status["free_heap"], minheap=status["min_free_heap"])
        for name in HARDWARE[2:]:
            out[name] = status[name]
    return out, counts["invalid_headers"]


def archive_windows(path, *, window_ms=100, guard_ms=1000, status_age_ms=250):
    width, age = window_ms * 1000, status_age_ms * 1000
    with closing(sqlite3.connect(database_path(path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        for session in db.execute("SELECT * FROM sessions"):
            if session["end_reason"] == "campaign_incomplete":
                raise ValueError(f"Incomplete campaign: {path}; inspect labels and remote execution before training")
            if session["ended_at_utc"] is None:
                raise ValueError(f"Archive is not closed: {path}; stop collector with Ctrl+C first")
            sid = session["session_id"]
            events = []
            event_times = [r[0] for r in db.execute("SELECT host_time_ns FROM events ORDER BY event_id")]
            clock_bad = any(b < a for a, b in zip(event_times, event_times[1:]))
            clock_bad |= db.execute(
                "SELECT 1 FROM (SELECT host_arrival_ns, LAG(host_arrival_ns) OVER (ORDER BY record_id) AS prior "
                "FROM records WHERE session_id=?) WHERE host_arrival_ns<prior LIMIT 1", (sid,)).fetchone() is not None
            for e in db.execute("SELECT host_time_ns, detail FROM events WHERE name='label_change' ORDER BY host_time_ns, event_id"):
                detail = json.loads(e["detail"])
                events.append((e["host_time_ns"], normalize_label(detail["label"])))
            boots = db.execute("SELECT DISTINCT boot_id FROM records WHERE session_id=?", (sid,)).fetchall()
            for boot_row in boots:
                boot = boot_row[0]
                states = [dict(r) for r in db.execute(
                    "SELECT r.device_us, r.host_arrival_ns, s.* FROM statuses s JOIN records r USING(record_id) "
                    "WHERE r.session_id=? AND r.boot_id=? ORDER BY r.device_us,r.record_id", (sid, boot))]
                if len(states) < 2:
                    continue  # no evidenced interval; never invent a silent zero-packet run
                stimes = [s["device_us"] for s in states]
                # Only whole windows bracketed by actual status samples are emitted.
                start = ((stimes[0] + width - 1) // width) * width
                end = (stimes[-1] // width) * width
                if (end - start) // width > 10_000_000:
                    raise ValueError("Unreasonable timestamp span; split or inspect this archive")
                gaps = []
                for table, gap in (("records", "stream_gap_before"), ("packets", "packet_gap_before")):
                    query = ("SELECT device_us, previous, gap FROM (SELECT r.device_us, "
                             "LAG(r.device_us) OVER (ORDER BY r.record_id) AS previous, "
                             f"{('r' if table == 'records' else 'p')}.{gap} AS gap FROM records r "
                             + ("JOIN packets p USING(record_id) " if table == "packets" else "")
                             + "WHERE r.session_id=? AND r.boot_id=?) WHERE gap>0")
                    for r in db.execute(query, (sid, boot)):
                        before = r["previous"] if r["previous"] is not None else r["device_us"]
                        gaps.append((min(before, r["device_us"]), max(before, r["device_us"])))
                merged = []
                for lo, hi in sorted(gaps):
                    if merged and lo <= merged[-1][1]:
                        merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
                    else:
                        merged.append((lo, hi))
                gap_ends = [hi for _, hi in merged]
                cursor = iter(db.execute(
                    "SELECT r.device_us,r.host_arrival_ns,r.flags,p.* FROM packets p JOIN records r USING(record_id) "
                    "WHERE r.session_id=? AND r.boot_id=? AND r.device_us>=? AND r.device_us<? "
                    "ORDER BY r.device_us,r.record_id", (sid, boot, start, end)))
                pending = next(cursor, None)
                for left in range(start, end, width):
                    right = left + width
                    packets = []
                    while pending is not None and pending["device_us"] < right:
                        packets.append(pending)
                        pending = next(cursor, None)
                    i0 = bisect_right(stimes, left) - 1
                    i1 = bisect_left(stimes, right) - 1  # strictly before end, no future features
                    i2 = bisect_left(stimes, right)
                    prior, latest, after = states[i0], states[i1], states[i2]
                    reasons = []
                    if events and clock_bad:
                        reasons.append("host_clock_rollback")
                    if left-prior["device_us"] > age or right-latest["device_us"] > age or after["device_us"]-right > age:
                        reasons.append("status_gap")
                    elif any(b-a > age for a, b in zip(stimes[i0:i2], stimes[i0+1:i2+1])):
                        reasons.append("status_gap")
                    for name in ("drop_pool_count", "invalid_count", "tx_fail_count", "status_drop_count"):
                        if ((after[name]-prior[name]) & 0xffffffff) != 0:
                            reasons.append(name)
                    gap_index = bisect_left(gap_ends, left)
                    if gap_index < len(merged) and merged[gap_index][0] < right:
                        reasons.append("sequence_gap")
                    out, invalid = features(packets, latest if right-latest["device_us"] <= age else None)
                    if invalid:
                        reasons.append("unusable_header")
                    # Arrival-clock bracketing is approximate, not clock synchronization.
                    arrivals = [prior["host_arrival_ns"], after["host_arrival_ns"]] + [p["host_arrival_ns"] for p in packets]
                    label, boundary = label_for_interval(session["label"], events, min(arrivals), max(arrivals), guard_ms*1_000_000)
                    if boundary:
                        reasons.append("label_boundary")
                    if events and clock_bad:
                        label = None
                    out["packets_per_second"] = len(packets) * 1_000_000 / width
                    yield {"schema": SCHEMA, "session_id": sid, "boot_id": boot,
                           "window_start_us": left, "window_ms": window_ms, "label": label,
                           "quality_ok": not reasons, "quality_reasons": reasons,
                           "invalid_headers": invalid, "features": out}


def build_windows(inputs, output, *, window_ms=100, guard_ms=1000, status_age_ms=250):
    if window_ms <= 0 or guard_ms < 0 or status_age_ms <= 0:
        raise ValueError("window/status age must be positive; guard must be nonnegative")
    paths = []
    for item in inputs:
        p = Path(item)
        paths.extend(sorted(p.glob("*/dataset.sqlite3")) if p.is_dir() and not (p / "dataset.sqlite3").exists() else [database_path(p)])
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    if not paths:
        raise ValueError("No raw archives found")
    # Reject duplicated sessions (e.g. archive copies) before creating output.
    sessions = set()
    source_info = []
    for path in paths:
        with closing(sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)) as db:
            archive_sessions = db.execute("SELECT session_id,ended_at_utc FROM sessions").fetchall()
            if len(archive_sessions) != 1:
                raise ValueError(f"Expected one capture session per archive: {path}")
            for sid, ended in archive_sessions:
                if sid in sessions:
                    raise ValueError(f"Duplicate session: {sid}")
                if ended is None:
                    raise ValueError(f"Archive is still open or was not cleanly stopped: {path}")
                sessions.add(sid)
            source_info.append({"path": str(path), "hello_variants": [json.loads(r[0]) for r in
                                db.execute("SELECT DISTINCT metadata_json FROM hellos")],
                                "end_reasons": [r[0] for r in db.execute("SELECT end_reason FROM sessions")]})
    dest = Path(output)
    dest.mkdir(parents=True, exist_ok=False)
    counts, labels, reasons = Counter(), Counter(), Counter()
    per_session = {}
    digest = hashlib.sha256()
    with (dest / "windows.jsonl").open("xb") as stream:
        for path in paths:
            for row in archive_windows(path, window_ms=window_ms, guard_ms=guard_ms, status_age_ms=status_age_ms):
                encoded = (json.dumps(row, ensure_ascii=False, allow_nan=False)+"\n").encode("utf-8")
                stream.write(encoded)
                digest.update(encoded)
                counts["windows"] += 1
                counts["quality_ok"] += row["quality_ok"]
                counts["unknown_label"] += row["label"] is None
                labels[row["label"] or "unknown"] += 1
                reasons.update(row["quality_reasons"])
                session_stats = per_session.setdefault(row["session_id"], {
                    "windows": 0, "quality_ok": 0, "labeled_quality_ok": 0})
                session_stats["windows"] += 1
                session_stats["quality_ok"] += row["quality_ok"]
                session_stats["labeled_quality_ok"] += row["quality_ok"] and row["label"] is not None
    manifest = {"schema": SCHEMA, "inputs": [str(p) for p in paths],
                "sessions": sorted(sessions), "window_ms": window_ms,
                "source_info": source_info,
                "guard_ms": guard_ms, "status_age_ms": status_age_ms,
                "sha256": digest.hexdigest(), "counts": dict(counts),
                "per_session": per_session,
                "labels": dict(labels), "quality_reasons": dict(reasons),
                "label_clock": "host reception with guard; NOT exact device/attack clock sync"}
    with (dest / "manifest.json").open("x", encoding="utf-8") as out:
        json.dump(manifest, out, ensure_ascii=False, indent=2)
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", help="Closed capture directories, SQLite files, or captures parent")
    p.add_argument("--out", required=True, help="NEW feature directory")
    p.add_argument("--window-ms", type=int, default=100)
    p.add_argument("--label-guard-ms", type=int, default=1000)
    p.add_argument("--max-status-age-ms", type=int, default=250)
    a = p.parse_args(argv)
    try:
        result = build_windows(a.inputs, a.out, window_ms=a.window_ms, guard_ms=a.label_guard_ms,
                               status_age_ms=a.max_status_age_ms)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Feature extraction failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["counts"].get("windows") else 1


if __name__ == "__main__":
    raise SystemExit(main())
