#!/usr/bin/env python3
"""Collect raw ESP32 packets + receive metadata + periodic hardware states.

  python scripts/serial_collector.py --port COM3 --out captures/run_001
  python scripts/serial_collector.py --port COM3 --label normal --standby
  python scripts/serial_collector.py --format legacy --port COM3 --baud 115200 --out old.csv

Do not run the IDF serial monitor at the same time. Raw mode requires the raw
capture firmware; a legacy syslog stream is preserved as wire bytes, not packets.
"""
import argparse
from contextlib import suppress
from datetime import datetime, timezone
import importlib
from pathlib import Path
import sqlite3
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from host.collector.raw_dataset import DatasetWriter


class SerialTransportError(RuntimeError):
    """Distinguishes port failures from filesystem OSErrors such as a full disk."""


def open_serial(serial_module, port, baud):
    """Set DTR/RTS before opening. Some OS/drivers may still pulse reset lines."""
    connection = serial_module.Serial(port=None, baudrate=baud, timeout=0.25)
    try:
        connection.dtr = False
        connection.rts = False
        connection.port = port
        connection.open()
        return connection
    except BaseException:
        with suppress(serial_module.SerialException, OSError):
            connection.close()
        raise


def _print_stats(dataset):
    stats = dataset.statistics()
    parser = stats["parser"]
    errors = sum(value for key, value in parser.items() if key.endswith("_errors"))
    print(f"bytes={dataset.offset} packets={dataset.counts['packets']} "
          f"states={dataset.counts['statuses']} hello={dataset.counts['hellos']} "
          f"decode_errors={errors} stream_gaps={stats['stream_sequence'].get('gaps', 0)} "
          f"packet_gaps={stats['packet_sequence'].get('gaps', 0)}", flush=True)
    status = stats["latest_status"]
    if status is not None:
        print(f"device boot={status['boot_id']} heap={status['free_heap']} "
              f"minheap={status['min_free_heap']} queue={status['queue_depth']} "
              f"queue_peak={status['queue_peak']} pool_free={status['pool_free']} "
              f"drop_pool={status['drop_pool_count']} invalid={status['invalid_count']} "
              f"tx_fail={status['tx_fail_count']} state_drop={status['status_drop_count']} "
              f"unavailable={status['payload_unavailable_count']} "
              f"truncated={status['truncated_count']}", flush=True)
    if dataset.offset and not parser.get("valid_records"):
        print("No valid NIDR records yet: check raw firmware mode and matching baud.",
              file=sys.stderr)


def collect(args, serial_module):
    serial_errors = (serial_module.SerialException, OSError)
    connection = None
    dataset = DatasetWriter(args.out, port=args.port, baud=args.baud, label=args.label,
                            max_status_age_ms=args.max_status_age_ms)
    last_flush = last_stats = time.monotonic()
    exit_code, end_reason = 0, "completed"
    try:
        print(f"Dataset: {dataset.path.resolve()}\nSession: {dataset.session_id}\n"
              f"Label: {args.label if args.label is not None else 'unknown (NULL)'}\n"
              "Ctrl+C stops and flushes the archive.", flush=True)
        while True:
            if connection is None:
                try:
                    connection = open_serial(serial_module, args.port, args.baud)
                except serial_errors as exc:
                    dataset.event("serial_open_failed", str(exc))
                    dataset.flush()
                    if not args.standby:
                        raise SerialTransportError(str(exc)) from exc
                    print(f"Waiting for {args.port}: {exc}", file=sys.stderr)
                    time.sleep(1)
                    continue
                dataset.event("serial_open", f"{args.port}@{args.baud}")
                print(f"Opened {args.port} at {args.baud} baud", flush=True)
            try:
                # Never depend on newlines: arbitrary binary data can contain them.
                waiting = connection.in_waiting
                data = connection.read(min(max(waiting, 1), 65536))
            except serial_errors as exc:
                dataset.connection_break(exc)
                with suppress(*serial_errors):
                    connection.close()
                connection = None
                if not args.standby:
                    raise SerialTransportError(str(exc)) from exc
                print(f"Serial disconnected; waiting to reconnect: {exc}", file=sys.stderr)
                time.sleep(1)
                continue
            if data:
                dataset.ingest(data, time.time_ns())
            now = time.monotonic()
            if now - last_flush >= 1:
                dataset.flush()
                last_flush = now
            if now - last_stats >= args.stats_interval:
                _print_stats(dataset)
                last_stats = now
    except KeyboardInterrupt:
        end_reason = "user_interrupt"
        print("Stopped.")
    except SerialTransportError as exc:
        exit_code, end_reason = 1, "serial_error"
        print(f"Serial error: {exc}", file=sys.stderr)
    except BaseException:
        end_reason = "collector_error"
        raise
    finally:
        try:
            if connection is not None:
                with suppress(*serial_errors):
                    connection.close()
        finally:
            try:
                _print_stats(dataset)
            finally:
                dataset.close(end_reason)
    return exit_code


def main(argv=None, *, serial_module=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--format", choices=("raw", "legacy"), default="raw")
    parser.add_argument("--port", required=True, help="For example COM3 or /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, help="Default: raw 921600, legacy 115200")
    parser.add_argument("--out", help="Raw: NEW output directory; legacy: CSV file")
    parser.add_argument("--standby", action="store_true", help="Retry port errors until Ctrl+C")
    parser.add_argument("--label", help="Constant experiment label; omitted means unknown, not normal")
    parser.add_argument("--max-status-age-ms", type=int, default=250,
                        help="Past state older than this is flagged stale in packet_samples")
    parser.add_argument("--stats-interval", type=float, default=5)
    args = parser.parse_args(argv)
    if args.format == "legacy":
        if args.label is not None:
            parser.error("--label is supported only by raw mode")
        if Path(args.out or "serial_capture.csv").exists():
            parser.error("Legacy output already exists; choose a NEW CSV file")
        forwarded = ["--port", args.port, "--baud", str(args.baud or 115200),
                     "--out", args.out or "serial_capture.csv"]
        if args.standby:
            forwarded.append("--standby")
        legacy = importlib.import_module("scripts.serial_collector_legacy")
        return legacy.main(forwarded) or 0
    args.baud = 921600 if args.baud is None else args.baud
    if args.baud <= 0 or args.max_status_age_ms < 0 or args.stats_interval <= 0:
        parser.error("baud/stats-interval must be positive; max-status-age-ms must be nonnegative")
    if args.out is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        args.out = str(ROOT / "captures" / f"{stamp}_{uuid.uuid4().hex[:8]}")
    if Path(args.out).exists():
        parser.error(f"Output already exists; choose a NEW directory: {args.out}")
    if serial_module is None:
        try:
            serial_module = importlib.import_module("serial")
        except ImportError:
            print("pyserial required: pip install pyserial", file=sys.stderr)
            return 1
    try:
        return collect(args, serial_module)
    except (OSError, sqlite3.Error) as exc:
        print(f"Cannot save dataset: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
