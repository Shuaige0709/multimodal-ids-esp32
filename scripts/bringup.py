#!/usr/bin/env python3
"""Unified collector launcher. Raw is default; legacy UDP remains explicit.

python scripts/bringup.py --port COM3 --label normal --standby
python scripts/bringup.py --mode legacy --wait-esp32 60
"""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, add_help=False)
    p.add_argument("--mode", choices=("raw", "legacy"), default="raw")
    args, rest = p.parse_known_args(argv)
    if args.mode == "legacy":
        from scripts import bringup_legacy
        saved = sys.argv
        try:
            sys.argv = ["bringup_legacy.py", *rest]
            return bringup_legacy.main() or 0
        finally:
            sys.argv = saved
    from scripts.serial_collector import main as collect
    if not any(arg.split("=", 1)[0] == "--live-state" for arg in rest) and "--help" not in rest and "-h" not in rest:
        rest += ["--live-state", str(ROOT / "data" / "raw_live_state.json")]
    return collect(rest)  # same process: Ctrl+C flushes the archive


if __name__ == "__main__":
    raise SystemExit(main())
