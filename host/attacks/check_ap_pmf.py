#!/usr/bin/env python3
"""Read one AP's advertised PMF policy from iw scan output; never infer negotiation."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess


def parse_scan(text, bssid):
    blocks = re.split(r'(?m)^BSS\s+', text)[1:]
    matching = [b for b in blocks if b[:17].lower() == bssid.lower()]
    if not matching:
        return {'status': 'unknown', 'reason': 'target_not_found'}
    observations = []
    for block in matching:
        rsn = False
        caps = None
        for line in block.splitlines()[1:]:
            expanded = line.expandtabs(8)
            if re.match(r'^\s*RSN:', line):
                rsn = True
                indent = len(expanded) - len(expanded.lstrip())
                continue
            if rsn and expanded.strip() and len(expanded) - len(expanded.lstrip()) <= indent:
                rsn = False
            if rsn:
                hit = re.search(r'\* Capabilities:.*\(0x([0-9a-fA-F]+)\)', line)
                if hit:
                    caps = int(hit[1], 16)
                    break
        if caps is None:
            observations.append({'status': 'unknown', 'reason': 'no_decodable_rsn_capabilities'})
        elif caps & 0x40 and not caps & 0x80:
            observations.append({'status': 'unknown', 'reason': 'inconsistent_rsn_capabilities'})
        else:
            observations.append({'status': 'required' if caps & 0x40 else
                                 'capable' if caps & 0x80 else 'not_advertised',
                                 'rsn_capabilities': f'0x{caps:04x}'})
    if len({o['status'] for o in observations}) != 1:
        return {'status': 'unknown', 'reason': 'conflicting_target_observations'}
    return observations[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='wlan0')
    parser.add_argument('--bssid', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.bssid):
        parser.error('Invalid target BSSID')
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        scan = subprocess.run(['iw', 'dev', args.interface, 'scan', 'flush'],
                              text=True, capture_output=True, timeout=25)
        args.output.joinpath('scan.txt').write_text(scan.stdout, encoding='utf-8')
        args.output.joinpath('stderr.txt').write_text(scan.stderr, encoding='utf-8')
        result = (parse_scan(scan.stdout, args.bssid) if scan.returncode == 0 else
                  {'status': 'unknown', 'reason': 'scan_failed', 'exit_code': scan.returncode})
    except (OSError, subprocess.TimeoutExpired) as error:
        result = {'status': 'unknown', 'reason': 'scan_failed', 'error': str(error)}
    result.update(bssid=args.bssid.upper(), interface=args.interface,
                  time=datetime.now().astimezone().isoformat(), evidence='AP advertisement, not negotiated PMF')
    args.output.joinpath('result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print({'capable': 'AP advertises PMF support. Proceed with Required firmware.',
           'required': 'AP requires PMF. Proceed with Required firmware.',
           'not_advertised': 'AP does not currently advertise PMF. Stop here unless router PMF can be enabled.',
           'unknown': 'Could not determine PMF. Do not treat this as unsupported or as a passed check.'}[result['status']])
    print('Saved evidence:', args.output)


if __name__ == '__main__':
    main()
