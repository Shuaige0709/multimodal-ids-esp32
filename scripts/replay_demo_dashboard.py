#!/usr/bin/env python3
"""Replay an existing UART log at original speed. No COM port or new recording."""
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.demo_dashboard import DashboardState, start_dashboard


def log_segment(source, begin, seconds):
    end = begin + timedelta(seconds=seconds)
    limit = source.stat().st_size
    with source.open('rb') as stream:
        while stream.tell() < limit:
            raw = stream.readline()
            if stream.tell() > limit or not raw.endswith(b'\n'):
                break
            stamp, sep, line = raw.decode('utf-8', errors='replace').rstrip('\r\n').partition(' ')
            if not sep:
                continue
            try:
                recorded = datetime.fromisoformat(stamp)
            except ValueError:
                continue
            if begin <= recorded <= end:
                yield recorded, line


class ReplayState(DashboardState):
    def __init__(self, source, begin, clock=time.monotonic):
        self.replay_clock = clock
        self.anchor = clock()
        self.frozen = None
        self.begin = begin
        self.source = Path(source).name
        super().__init__(clock=self.elapsed,
                         wall_clock=lambda: begin + timedelta(seconds=self.elapsed()))

    def elapsed(self):
        return self.frozen if self.frozen is not None else self.replay_clock() - self.anchor

    def finish(self):
        self.frozen = self.elapsed()

    def snapshot(self):
        result = super().snapshot()
        result['presentation'] = {
            'mode': 'recorded', 'source': self.source, 'finished': self.frozen is not None,
            'time': (self.begin + timedelta(seconds=self.elapsed())).isoformat(timespec='seconds'),
        }
        return result


def main():
    from scripts.serial_collector import parse_sd
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--from', dest='begin', type=datetime.fromisoformat, required=True)
    parser.add_argument('--seconds', type=int, default=125)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error('--seconds must be 1..300')
    # Read and validate the bounded segment before starting HTTP or the clock.
    lines = list(log_segment(args.log, args.begin, args.seconds))
    if not lines:
        parser.error('No complete log records in the requested time range')
    state = ReplayState(args.log, args.begin)
    state.transport(True)
    server = start_dashboard(state, '0.0.0.0', args.port)
    print(f'RECORDED DATA, original speed: {args.log.name}', flush=True)
    print(f'Open http://localhost:{server.server_port}; Ctrl+C stops playback.', flush=True)
    try:
        for stamp, line in lines:
            due = (stamp - args.begin).total_seconds()
            while state.elapsed() < due:
                time.sleep(max(0, min(.05, due - state.elapsed())))
            state.ingest(line, parse_sd(line))
        state.finish()
        print('Playback finished. Page remains available; Ctrl+C to close.', flush=True)
        while True:
            time.sleep(.25)
    except KeyboardInterrupt:
        print('Playback stopped.')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
