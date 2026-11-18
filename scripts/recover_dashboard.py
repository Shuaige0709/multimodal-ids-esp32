#!/usr/bin/env python3
"""Rebuild a historical dashboard snapshot from the collector's timestamped log.

No COM port or web server is opened. The original files are never modified.
"""
import argparse
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.demo_dashboard import DashboardState, save_dashboard_snapshot


def recover(source, output):
    # Use exactly the live collector's schema, including malformed-line rejection.
    from scripts.serial_collector import parse_sd
    source, output = Path(source), Path(output)
    if output.exists():
        raise FileExistsError(f'Output already exists: {output}')
    size = source.stat().st_size
    current = {'time': None, 'elapsed': 0.0}
    state = None
    first = None
    count = windows = 0
    with source.open('rb') as stream:
        while stream.tell() < size:
            raw = stream.readline()
            if stream.tell() > size or not raw.endswith(b'\n'):
                break  # Exclude a partial line when the collector is still writing.
            line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
            stamp, sep, console = line.partition(' ')
            try:
                timestamp = datetime.fromisoformat(stamp)
            except ValueError:
                continue
            if not sep:
                continue
            if first is None:
                first = timestamp
                current['time'] = timestamp
                state = DashboardState(clock=lambda: current['elapsed'], wall_clock=lambda: current['time'])
                state.transport(True)
            current['time'] = timestamp
            current['elapsed'] = max(current['elapsed'], (timestamp - first).total_seconds())
            row = parse_sd(console)
            if row is not None:
                windows += 1
            state.ingest(console, row)
            count += 1
    if state is None:
        raise ValueError(f'No timestamped UART lines found in {source}')
    snapshot = save_dashboard_snapshot(state, output, {
        'reconstructed': True, 'source_log': str(source.resolve()),
        'source_bytes_at_start': size, 'processed_lines': count, 'parsed_windows': windows,
        'as_of': current['time'].isoformat(),
        'note': 'Historical observation as of the last complete log line; not a live status.',
    })
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    output = args.out or args.log.with_suffix('').with_name(args.log.with_suffix('').name + '.recovered.dashboard.json')
    try:
        result = recover(args.log, output)
    except (OSError, ValueError) as e:
        parser.exit(1, f'{e}\n')
    print(f'Recovered: {output}')
    print(f"As of: {result['export']['as_of']}; alerts: {result['total']}; mode: {result['protection']['mode']}")


if __name__ == '__main__':
    main()
