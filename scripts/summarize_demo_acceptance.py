"""Summarize the two existing functional campaigns. Never opens a device."""
import csv
from datetime import datetime, timedelta
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    'On': 'DEFENSE_On_Optional_20261118_113635.csv',
    'Off': 'DEFENSE_Off_Optional_20261118_132554.csv',
}


def summarize(path):
    intervals = []
    current = None
    with path.open(encoding='utf-8-sig', newline='') as stream:
        for row in csv.DictReader(stream):
            kind = row['attack_type'] if row['label'] == '1' else None
            if kind:
                if current is None or current['type'] != kind:
                    current = {'type': kind, 'start': row['timestamp'], 'end': row['timestamp'],
                               'windows': 0, 'alarm_windows': 0}
                    intervals.append(current)
                current['end'] = row['timestamp']
                current['windows'] += 1
                current['alarm_windows'] += int(row.get('pred_attack') == '1')
            else:
                current = None
    records = []
    with Path(str(path) + '.log').open(encoding='utf-8', errors='replace') as stream:
        for line in stream:
            if not any(token in line for token in ('[ARP_PROBE]', '[ARP_GARP]', 'WiFi disconnected')):
                continue
            stamp, _, body = line.partition(' ')
            try:
                timestamp = datetime.fromisoformat(stamp)
            except ValueError:
                continue
            records.append((timestamp, body, dict(re.findall(r'(\w+)=([\w:.-]+)', body))))
    for interval in intervals:
        start, end = (datetime.fromisoformat(interval[k]) for k in ('start', 'end'))
        inside = [(body, fields) for timestamp, body, fields in records if start <= timestamp <= end]
        after = [(body, fields) for timestamp, body, fields in records if end < timestamp <= end + timedelta(seconds=30)]
        interval['seconds'] = round((end - start).total_seconds(), 3)
        for name, selection in [('during', inside), ('after_30s', after)]:
            probes = [fields for body, fields in selection if '[ARP_PROBE]' in body]
            interval[name] = {
                'ping_ok': sum(p.get('result') == 'ok' for p in probes),
                'ping_timeout': sum(p.get('result') == 'timeout' for p in probes),
                'ping_error': sum(p.get('result') == 'error' for p in probes),
                'garp_sent': sum('[ARP_GARP]' in body and fields.get('action') == 'sent' for body, fields in selection),
                'disconnect_logs': sum('WiFi disconnected' in body for body, fields in selection),
            }
    dashboard = json.loads(Path(str(path) + '.dashboard.json').read_text(encoding='utf-8-sig'))
    return {'csv': str(path.relative_to(ROOT)).replace('\\', '/'),
            'intervals': intervals, 'outages': dashboard['connection']['outages'],
            'wireless': dashboard['protection'].get('wireless')}


def main():
    result = {mode: summarize(ROOT / 'data/raw' / filename) for mode, filename in FILES.items()}
    output = ROOT / 'docs/demo_acceptance_results_20261118.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    for mode, run in result.items():
        print(mode, run['wireless'])
        for interval in run['intervals']:
            print(interval['type'], interval['seconds'], interval['alarm_windows'], '/', interval['windows'], interval['during'], 'post', interval['after_30s'])
        print('Outages', [(o['start'], o['duration'], o['attempts']) for o in run['outages']])
    print('Saved', output)


if __name__ == '__main__':
    main()
