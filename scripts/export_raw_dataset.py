#!/usr/bin/env python3
"""Export one JSONL row per packet with its most recent prior hardware state.

This is an optional inspection/offline feature-extraction starting point, not
the old 17-feature training format. The original SQLite archive stays intact.
Payload and SDK metadata bytes are represented as hex only in this export;
wire transport and the original database keep bytes without hex expansion.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import sys


def export_dataset(dataset, output, *, max_status_age_ms=None, omit_payload=False):
    source = Path(dataset)
    if source.is_dir():
        source = source / "dataset.sqlite3"
    # mode=ro avoids accidentally creating a new empty database after a typo.
    database = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
    database.row_factory = sqlite3.Row
    count = 0
    try:
        if max_status_age_ms is not None and max_status_age_ms < 0:
            raise ValueError("max_status_age_ms must be nonnegative")
        with Path(output).open("x", encoding="utf-8", newline="\n") as out:
            for record in database.execute("SELECT * FROM packet_samples ORDER BY record_id"):
                row = dict(record)
                if max_status_age_ms is not None:
                    row["status_stale"] = int(row["status_age_us"] is not None and
                                             row["status_age_us"] > max_status_age_ms * 1000)
                    row["status_valid"] = int(not row["status_missing"] and not row["status_stale"])
                # Stale state values remain explicitly flagged. Do not silently
                # substitute zeros or call unknown labels normal during training.
                for name in ("payload", "rx_ctrl_raw"):
                    value = row.pop(name)
                    if name != "payload" or not omit_payload:
                        row[name + "_hex"] = value.hex()
                out.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
    finally:
        database.close()
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="Dataset directory or dataset.sqlite3")
    parser.add_argument("--out", required=True, help="New JSONL file; existing files are never overwritten")
    parser.add_argument("--max-status-age-ms", type=int, help="Override stale threshold only in this export")
    parser.add_argument("--omit-payload", action="store_true", help="Smaller metadata-only inspection export")
    args = parser.parse_args(argv)
    try:
        count = export_dataset(args.dataset, args.out, max_status_age_ms=args.max_status_age_ms,
                               omit_payload=args.omit_payload)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return 1
    print(f"Exported {count} packet rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
