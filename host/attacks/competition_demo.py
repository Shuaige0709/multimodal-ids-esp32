#!/usr/bin/env python3
"""Two live, operator-triggered demonstrations on the provisioned AP and ESP32."""
import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
ATTACKS = ROOT / 'host/attacks'


def load_profile(path):
    c = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    for key in ('esp32_ip', 'gateway_ip', 'windows_hostonly_ip'):
        address = ipaddress.ip_address(c[key])
        if address.version != 4 or not address.is_private or address.is_unspecified or address.is_loopback:
            raise ValueError(f'{key} must be a private, non-loopback IPv4 address')
    if c['esp32_ip'] == c['gateway_ip']:
        raise ValueError('ESP32 and gateway must differ')
    for key in ('esp32_mac', 'gateway_mac', 'ap_bssid'):
        value = c[key]
        if not re.fullmatch(r'(?:[\da-fA-F]{2}:){5}[\da-fA-F]{2}', value) or value == '00:00:00:00:00:00' or int(value[:2], 16) & 1:
            raise ValueError(f'Invalid unicast MAC: {key}')
    for key in ('wifi_interface', 'monitor_interface', 'hostonly_interface'):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', c[key]):
            raise ValueError(f'Invalid interface: {key}')
    if not 1 <= c['channel'] <= 13 or not 1 <= len(c['ssid'].encode()) <= 32:
        raise ValueError('Invalid channel or SSID')
    for key in ('serial_label_port', 'dashboard_port'):
        if not 1024 <= c[key] <= 65535:
            raise ValueError(f'Invalid port: {key}')
    if not 10 <= c['arp_seconds'] <= 60 or not 1 <= c['deauth_batches'] <= 5 or not 5 <= c['recovery_seconds'] <= 60:
        raise ValueError('Invalid bounded demonstration duration')
    return c


def environment(c):
    return {**os.environ, 'NIDS_SSID': c['ssid'], 'NIDS_ESP32_IP': c['esp32_ip'],
            'NIDS_ESP32_MAC': c['esp32_mac'], 'NIDS_GATEWAY_IP': c['gateway_ip'],
            'NIDS_BSSID': c['ap_bssid'], 'NIDS_WIFI_CHANNEL': str(c['channel']),
            'NIDS_WIFI_IFACE': c['wifi_interface'], 'NIDS_MON_IFACE': c['monitor_interface'],
            'NIDS_HOSTONLY_IFACE': c['hostonly_interface'], 'NIDS_WIN_GATEWAY': c['windows_hostonly_ip'],
            'NIDS_LABEL_HOST': c['windows_hostonly_ip'], 'NIDS_LABEL_PORT': str(c['serial_label_port']),
            'NIDS_SERIAL_LABEL_HOST': c['windows_hostonly_ip'], 'NIDS_SERIAL_LABEL_PORT': str(c['serial_label_port']),
            'NIDS_ARP_DURATION': str(c['arp_seconds']), 'NIDS_DEAUTH_BATCHES': str(c['deauth_batches']),
            'NIDS_SKIP_AP_SCAN': '1', 'NIDS_DEMO_STRICT': '1'}


def validate_live(d, c, require_unlocked=False, require_connected=True):
    if d.get('presentation', {}).get('mode') == 'recorded':
        raise ValueError('Recorded playback is open. Start the LIVE USB dashboard instead.')
    if not d.get('serial') or d.get('age') is None or d['age'] >= 5:
        raise ValueError('No fresh live USB data')
    if not require_connected:
        return
    p, w = d.get('protection', {}), d.get('protection', {}).get('wireless', {})
    if not d.get('wifi_fresh') or d.get('wifi') != 'up':
        raise ValueError('ESP32 Wi-Fi is not confirmed connected')
    if not p.get('fresh') or p.get('mode') != 'on' or not p.get('wireless_fresh') or w.get('binding') != 'on':
        raise ValueError('Live ARP protection and trusted AP binding must both be On')
    if p.get('device_ip') != c['esp32_ip'] or p.get('target') != c['gateway_ip']:
        raise ValueError(
            f"Live IP/gateway differs from network.json: live ESP32={p.get('device_ip')}, "
            f"gateway={p.get('target')}; configured ESP32={c['esp32_ip']}, "
            f"gateway={c['gateway_ip']}. Update the profile or DHCP reservation.")
    if w.get('bssid', '').lower() != c['ap_bssid'].lower() or str(d.get('latest', {}).get('channel')) != str(c['channel']):
        raise ValueError('Live AP/channel differs from network.json')
    if d.get('latest', {}).get('host_mac', '').lower() != c['esp32_mac'].lower():
        raise ValueError('Live device MAC differs from network.json')
    if p.get('communication') not in ('reachable', 'recovered'):
        raise ValueError('Wait for verified router replies before the demonstration')
    if require_unlocked and (p.get('action') == 'locked' or p.get('repairs', 0)):
        raise ValueError('ARP was already repaired this boot. Stop attacks, restart the ESP32, then rerun preparation.')


def live_status(c):
    with urlopen(f"http://{c['windows_hostonly_ip']}:{c['dashboard_port']}/api/status", timeout=2) as response:
        return json.load(response)


def monitor_name(iw_text, c):
    for block in re.split(r'\bInterface\s+', iw_text)[1:]:
        name = block.splitlines()[0].strip()
        if name in (c['wifi_interface'], c['monitor_interface']) and re.search(r'^\s*type monitor\s*$', block, re.M):
            return name
    raise RuntimeError('The configured adapter did not enter monitor mode')


def resolve_live_target(d, c, unlocked=False):
    """Resolve DHCP address only after validating the provisioned identities.

    Gateway/AP identity remains provisioned: never learn a trusted router from
    whatever the network advertises during an ARP demonstration.
    """
    candidate = dict(c)
    value = d.get('protection', {}).get('device_ip')
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError('Live ESP32 address is not available yet') from None
    if address.version != 4 or not address.is_private or address.is_unspecified or address.is_loopback:
        raise ValueError('Live ESP32 address must be a private, non-loopback IPv4 address')
    candidate['esp32_ip'] = str(address)
    if candidate['esp32_ip'] == candidate['gateway_ip']:
        raise ValueError('Live ESP32 address cannot equal the gateway')
    validate_live(d, candidate, require_unlocked=unlocked)
    return candidate


def ready(c, unlocked=False, seconds=20, discover=False):
    deadline = time.monotonic() + seconds
    error = None
    while time.monotonic() < deadline:
        try:
            d = live_status(c)
            if discover:
                resolved = resolve_live_target(d, c, unlocked=unlocked)
                c.update(resolved)
                print('Live target verified:', c['esp32_ip'], 'MAC:', c['esp32_mac'])
            else:
                validate_live(d, c, require_unlocked=unlocked)
            return d
        except (OSError, ValueError) as problem:
            error = problem
            if isinstance(problem, ValueError) and ('already repaired' in str(problem) or 'playback' in str(problem)):
                break
            time.sleep(.5)
    raise RuntimeError(f'Not ready: {error}')


def stop_process(child):
    if child is None or child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()


def stop_label(c, kind):
    payload = json.dumps({'status': 'STOP', 'attack_type': kind, 'timestamp': time.time()}).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, (c['windows_hostonly_ip'], c['serial_label_port']))


def run_attack(c, env, script, kind):
    log_dir = ROOT / 'data/demo_stage'
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / (datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + kind + '.log')
    child = None
    observed = {'alerts': set(), 'wifi_down': False, 'router_replies_seen': False}
    before = live_status(c).get('total', 0)
    interrupted = False
    timed_out = False
    # An upper bound also covers tool start-up; it is not a detector threshold.
    deadline = time.monotonic() + (c['arp_seconds'] + 20 if kind == 'ARP_SPOOF' else 45)
    try:
        with log.open('w', encoding='utf-8') as output:
            child = subprocess.Popen(['bash', str(ATTACKS / script)], env=env,
                                     stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            print('Attack running. Press Enter to stop early, or wait for automatic stop.', flush=True)
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    interrupted = True
                    timed_out = True
                    print('Tool time limit reached; stopping.')
                    break
                if select.select([sys.stdin], [], [], .2)[0]:
                    line = sys.stdin.readline()
                    if line == '':
                        raise RuntimeError('Interactive terminal input was lost')
                    interrupted = True
                    break
                try:
                    d = live_status(c)
                    validate_live(d, c, require_connected=False)
                    observed['alerts'].update(e['type'] for e in d.get('events', []) if e['id'] > before)
                    observed['wifi_down'] |= d.get('wifi_fresh', False) and d.get('wifi') == 'down'
                    observed['router_replies_seen'] |= d.get('protection', {}).get('communication') in ('reachable', 'recovered')
                except OSError:
                    pass  # Serial capture continues on Windows; do not fabricate status.
            stop_process(child)
            if timed_out:
                raise RuntimeError(f'Tool exceeded its time limit; see {log}')
            if not interrupted and child.returncode != 0:
                raise RuntimeError(f'Tool failed; see {log}')
    finally:
        stop_process(child)
        stop_label(c, kind)
    print('Attack stopped. Live observations:',
          ', '.join(sorted(observed['alerts'])) or 'no new alert observed',
          '| Wi-Fi outage observed:', observed['wifi_down'])
    print('These observations are not an automatic protection-success verdict.')
    print('Tool log:', log)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, default=ROOT / 'demo/competition/network.json')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    c = load_profile(args.profile)
    env = environment(c)
    if args.dry_run:
        print('PLAN ONLY: no commands, requests, labels or attacks executed.')
        print('Target: live UART IPv4 discovery for', c['esp32_mac'], 'AP:', c['ap_bssid'], 'channel:', c['channel'])
        print('Prepare managed Wi-Fi; verify LIVE USB, On policy and clean ARP state.')
        print('Enter -> one-way ARP:', c['arp_seconds'], 'seconds, or Enter to stop early.')
        print('Auto-switch to monitor; Enter -> targeted deauth:', c['deauth_batches'], 'batches.')
        print('Observe actual recovery; restore managed Wi-Fi and original forwarding on exit.')
        return
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('Run on Kali: sudo python3 host/attacks/competition_demo.py')
    if not sys.stdin.isatty():
        parser.error('Use an interactive terminal; do not pipe input into live attacks')
    for tool in ('bash', 'iw', 'ip', 'nmcli', 'arpspoof', 'aireplay-ng', 'timeout', 'sysctl', 'python3'):
        if not shutil.which(tool):
            parser.error(f'Missing tool: {tool}')
    previous_forward = subprocess.check_output(['sysctl', '-n', 'net.ipv4.ip_forward'], text=True).strip()
    changed_radio = False
    try:
        changed_radio = True
        subprocess.run(['bash', str(ATTACKS / 'prepare_wifi.sh'), 'managed'], env=env, check=True)
        link = subprocess.check_output(['iw', 'dev', c['wifi_interface'], 'link'], text=True)
        if not re.search(r'^\s*SSID:\s*' + re.escape(c['ssid']) + r'\s*$', link, re.M):
            raise RuntimeError('Kali is not associated with the configured SSID')
        ready(c, unlocked=True, discover=True)
        env = environment(c)
        print('\nREADY. Live data confirmed; ARP protection On. No attack is running.')
        if args.prepare_only:
            return
        if input('Press Enter for live ARP, or q to quit: ').strip().lower() == 'q':
            return
        ready(c, unlocked=True, seconds=5)
        run_attack(c, env, 'arp_guard_test.sh', 'ARP_SPOOF')
        print('\nPreparing wireless demonstration. Keep the dashboard visible.')
        subprocess.run(['bash', str(ATTACKS / 'prepare_wifi.sh'), 'monitor'], env=env, check=True)
        env['NIDS_MON_IFACE'] = monitor_name(subprocess.check_output(['iw', 'dev'], text=True), c)
        ready(c)
        if input('Press Enter for live deauthentication, or q to finish: ').strip().lower() == 'q':
            return
        run_attack(c, env, 'attack_deauth.sh', 'DEAUTH')
        print('\nWaiting for actual Wi-Fi and router-response recovery...')
        try:
            recovered = ready(c, seconds=c['recovery_seconds'])
            print('Live connectivity is available. Recorded Wi-Fi outage count:', recovered['connection']['total'])
        except RuntimeError:
            print('Recovery was not confirmed within the observation period. Show that result as-is.')
        print('Live demonstration finished. No replay was used.')
    except KeyboardInterrupt:
        print('\nStopping the live demonstration.')
    finally:
        subprocess.run(['sysctl', '-w', f'net.ipv4.ip_forward={previous_forward}'], stdout=subprocess.DEVNULL, check=False)
        if changed_radio:
            subprocess.run(['bash', str(ATTACKS / 'prepare_wifi.sh'), 'managed'], env=env, check=False)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f'Demo stopped: {error}', file=sys.stderr)
        sys.exit(1)
