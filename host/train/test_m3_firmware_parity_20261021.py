#!/usr/bin/env python3
"""Compare frozen Python M3 replay with the firmware C policy on recorded windows."""
from __future__ import annotations

import csv
import ctypes as ct
import subprocess
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from host.train.export_m3_model_20261021 import render
from host.train.false_alarm_semantic_gate_20261015 import rolling_hits
from host.train.m2_event_replay_20261020 import supported_masks, train_experts
from host.train.m3_attack_expansion_eval_20261021 import (
    CAPTURES, beacon_mask, event_mask, gateway_excursion_edges,
)
from host.train.model_sweep_20261015 import load_run

ROOT = Path(__file__).resolve().parents[2]
HOLDOUT = ROOT / "data" / "raw" / "m3_expansion_holdout"
RUNS = {name: CAPTURES[name] for name in ("T1", "P1", "K2", "K1")}
RUNS.update({name: next(HOLDOUT.glob(f"{name}_*.csv")) for name in ("N1", "A2", "C2")})


def snapshots(rows: list[dict]) -> dict[pd.Timestamp, dict]:
    result = {}
    for row in rows:
        result[pd.Timestamp(row["timestamp"]).floor("100ms")] = row
    return result


def check_run(lib: ct.CDLL, name: str, path: Path, fitted: tuple) -> dict:
    frame = load_run(name, path)
    features, clf = fitted
    vote = clf.predict(frame[features].to_numpy(dtype=np.float32)).astype(bool)
    stable = rolling_hits(frame, vote, "700ms", 4)
    _, rf = supported_masks(frame, stable)
    beacon = beacon_mask(frame)
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    arp = event_mask(frame, gateway_excursion_edges(rows))
    by_time = snapshots(rows)
    lib.m3_parity_reset()
    disagreements = []
    actual_hits = np.zeros(4, dtype=int)
    for index, row in enumerate(frame.itertuples(index=False)):
        raw = by_time[pd.Timestamp(row.time)]
        mac_str = (raw.get("gw_mac") or "-").upper()
        valid = mac_str not in ("", "-", "00:00:00:00:00:00")
        mac = (ct.c_uint8 * 6)(*(bytes.fromhex(mac_str.replace(":", "")) if valid else bytes(6)))
        encoded = lib.m3_parity_step(
            int(pd.Timestamp(row.time).value // 1_000_000),
            *[float(getattr(row, field)) for field in (
                "total_packets", "packet_density", "beacon_packets", "deauth_targeted",
                "auth_packets", "unique_bssid", "twin_bssid")],
            int(row.probe_packets), int(row.beacon_packets), int(row.deauth_targeted),
            int(row.twin_bssid), int(float(raw.get("gw_flip") or 0)),
            int(float(raw.get("reconn") or 0)), mac, int(valid),
        )
        actual = ((encoded >> 8) & 1, bool(encoded & 1), bool(encoded & 2), bool(encoded & 4))
        expected = (int(vote[index]), bool(rf[index]), bool(beacon[index]), bool(arp[index]))
        actual_hits += actual
        if actual != expected:
            disagreements.append((str(row.time), expected, actual))
    if disagreements:
        raise AssertionError(f"{name}: {len(disagreements)} differing windows; first {disagreements[:5]}")
    return {"windows": len(frame), "raw_rf_beacon_arp_hits": actual_hits.tolist()}


class M3FirmwareParity(unittest.TestCase):
    def test_m3_source_csv_parsers(self) -> None:
        from datetime import datetime

        from host.collector.nids_collector import parse_syslog_meta
        from scripts.serial_collector import HEADER, canonical_row, parse_sd

        with RUNS["N1"].open(newline="", encoding="utf-8") as source:
            raw = next(csv.DictReader(source))["raw"]
        raw = raw.replace('gw_flip="0"', 'gw_flip="0" m3src="4"', 1)
        serial = parse_sd(raw)
        pi, _ = parse_syslog_meta(raw)
        self.assertIsNotNone(serial)
        self.assertIsNotNone(pi)
        self.assertEqual(serial["m3src"], "4")
        self.assertEqual(pi["m3src"], "4")
        row = canonical_row(serial, 0, "NONE", datetime.now(), raw)
        self.assertEqual(len(row), len(HEADER))
        self.assertEqual(row[HEADER.index("m3src")], "4")

    def test_recorded_windows(self) -> None:
        self.assertEqual((ROOT / "main" / "m3_model.h").read_text(encoding="ascii"), render())
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "m3_parity.dll"
            subprocess.run([
                "gcc", "-std=c11", "-O2", "-shared", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "main"), str(ROOT / "main" / "nids_m3.c"),
                str(ROOT / "host" / "train" / "m3_parity_bridge.c"), "-o", str(dll),
            ], check=True)
            lib = ct.CDLL(str(dll))
            lib.m3_parity_step.argtypes = [ct.c_uint64] + [ct.c_float] * 7 + [ct.c_uint32] * 6 + [ct.POINTER(ct.c_uint8), ct.c_int]
            lib.m3_parity_step.restype = ct.c_uint
            lib.m3_parity_state_bytes.restype = ct.c_uint
            try:
                fitted = train_experts()[0]
                results = {name: check_run(lib, name, path, fitted) for name, path in RUNS.items()}
                print(f"M3 C state bytes={lib.m3_parity_state_bytes()} results={results}")
            finally:
                if hasattr(ct, "windll"):
                    ct.windll.kernel32.FreeLibrary(ct.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
