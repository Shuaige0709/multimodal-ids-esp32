#!/usr/bin/env python3
"""
bringup.py - start the syslog collector on Windows (or any Python host).

Preferred entry on Windows:  .\\scripts\\session_windows.ps1
(which calls this file). On Pi/Linux use:  ./scripts/bringup.sh

Usage:
  python scripts/bringup.py
  python scripts/bringup.py --wait-esp32 60
  python scripts/bringup.py --no-collector
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

from host.paths import LIVE_STATE_FILE  # noqa: E402

SSID = os.environ.get("NIDS_SSID", "302")
LABEL_HOST = os.environ.get("NIDS_LABEL_HOST", "192.168.124.1")
LABEL_PORT = os.environ.get("NIDS_LABEL_PORT", "9999")


def load_live_state():
    try:
        with open(LIVE_STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def print_banner():
    state = load_live_state()
    print("=" * 60)
    print(" NIDS bring-up (collector on this machine)")
    print("=" * 60)
    print(f"  live_state : {LIVE_STATE_FILE}")
    print(f"  ESP32 IP   : {state.get('esp32_ip') or '(none yet)'}")
    print(f"  ESP32 MAC  : {state.get('esp32_mac') or '(none yet)'}")
    print(f"  SSID       : {SSID}")
    print(f"  Label dest : {LABEL_HOST}:{LABEL_PORT}  (Kali should send START/STOP here)")
    print()
    print("Firmware (ESP-IDF shell):")
    print(f"  cd {ROOT}")
    print("  idf.py build flash monitor")
    print()
    print("Notes:")
    print(f"  * This PC Wi-Fi SSID should match firmware ('{SSID}').")
    print("  * On Pi instead? Use ./scripts/bringup.sh (same job).")
    print("  * Deauth OOB: prefer Pi collector or SYSlOG_MODE=2 serial.")
    print("=" * 60)


def wait_for_esp32(timeout_sec):
    print(f"Waiting up to {timeout_sec}s for ESP32 in {LIVE_STATE_FILE} ...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        state = load_live_state()
        if state.get("esp32_ip"):
            print(f"  ESP32 live: IP={state.get('esp32_ip')} MAC={state.get('esp32_mac')}")
            return True
        time.sleep(1.0)
    print("  Timed out - is the firmware flashing and joined to the hotspot?")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-collector", action="store_true")
    ap.add_argument("--wait-esp32", type=int, default=0)
    args = ap.parse_args()

    print_banner()
    if args.no_collector:
        return 0

    collector = os.path.join(ROOT, "host", "collector", "nids_collector.py")
    print(f"\nStarting collector: {collector}")
    print("(Ctrl+C stops the collector)\n")
    proc = subprocess.Popen([sys.executable, collector], cwd=ROOT)

    try:
        if args.wait_esp32 > 0:
            time.sleep(2)
            wait_for_esp32(args.wait_esp32)
        proc.wait()
    except KeyboardInterrupt:
        print("\nStopping collector...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
