"""One isolated-lab session: USB collector + SSH-controlled existing SYN script.

Default is read-only preflight. --run explicitly enables the experiment.
No VM start, password storage, sudoers edits, firewall edits, or automatic deployment.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FILES = ('host/attacks/syn_flood.sh', 'host/attacks/netconfig.sh', 'scripts/raw_label.py')


def ssh_args(a, command):
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=3', f'{a.kali_user}@{a.kali_host}', command]


def remote_env(a, target):
    values = dict(NIDS_ESP32_IP=target, NIDS_SYN_IFACE=a.attack_iface,
                  NIDS_LABEL_HOST=a.label_host, NIDS_LABEL_PORT='9999',
                  NIDS_REQUIRE_LABEL_ACK='1', NIDS_SKIP_HOSTONLY='1')
    return '; '.join('export '+k+'='+shlex.quote(v) for k, v in values.items())


def preflight(a):
    # Compare normalized sources: CRLF on Windows is acceptable, CRLF shell files on Kali aren't.
    check = "import hashlib,pathlib,json; print(json.dumps({p:hashlib.sha256(pathlib.Path(p).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for p in " + repr(FILES) + "}))"
    prefix = 'cd '+shlex.quote(a.kali_project)+' && '
    result = run_check(a, prefix+'python3 -c '+shlex.quote(check), 'Kali project/files')
    hashes = json.loads(result.stdout)
    for name in FILES:
        expected = hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        if hashes.get(name) != expected:
            raise ValueError(f'Kali file differs: {name}. Deploy current files first; no attack started.')
    script = shlex.quote(a.kali_project+'/host/attacks/syn_flood.sh')
    cmd = (prefix+'command -v hping3 >/dev/null && command -v timeout >/dev/null && '
           'bash -n host/attacks/syn_flood.sh && '
           'test -x host/attacks/syn_flood.sh && '
           "! grep -q " + shlex.quote('\r') + ' host/attacks/syn_flood.sh && '
           'ip -4 addr show dev '+shlex.quote(a.attack_iface)+" | grep -q 'inet ' && "
           'sudo -n -l '+script+' >/dev/null')
    run_check(a, cmd, 'Kali tools/IPv4 interface/sudo')


def run_check(a, command, stage):
    result = subprocess.run(ssh_args(a, command), capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or 'Remote check returned no diagnostic output.'
        raise RuntimeError(f'{stage} failed (exit {result.returncode}):\n{detail}')
    return result


def read_live(path, collector):
    if collector.poll() is not None:
        raise RuntimeError('Collector exited; see collector.err.log')
    for attempt in range(3):
        try:
            state = json.loads(path.read_text(encoding='utf-8'))
            break
        except PermissionError:
            if attempt == 2:
                return None
            time.sleep(0.01)
        except (OSError, ValueError):
            return None
    if not state.get('active') or time.time_ns()-state['updated_ns'] > 8_000_000_000:
        return None
    if time.time_ns()-state.get('hello_received_ns', 0) > 6_000_000_000:
        return None
    if not state.get('esp32_ip') or not state['statistics']['records'].get('packets'):
        return None
    return state


def verify_events(path):
    with sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True) as db:
        rows = list(db.execute("SELECT detail,host_time_ns FROM events WHERE name='label_change' ORDER BY event_id"))
        events = [json.loads(r[0]) for r in rows]
        if len(events) != 2 or events[0].get('action') != 'START' or events[0].get('label') != 'syn_flood' or events[1].get('action') != 'STOP':
            raise RuntimeError('Missing/ambiguous START and STOP events; inspect archive before training')
        for table in ('packets', 'statuses'):
            if not db.execute(f'SELECT count(*) FROM {table} JOIN records USING(record_id) '
                              'WHERE host_arrival_ns BETWEEN ? AND ?', (rows[0][1], rows[1][1])).fetchone()[0]:
                raise RuntimeError(f'No {table} during labeled experiment')


def log_tail(path):
    """Bound memory even if the remote tool produces a large log."""
    try:
        with path.open('rb') as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell()-8192))
            return stream.read().decode('utf-8', errors='replace').strip()
    except OSError as exc:
        return f'Cannot read {path}: {exc}'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kali-host', default='192.168.56.101')
    p.add_argument('--kali-user', default='hao')
    p.add_argument('--kali-project', default='/home/hao/桌面/multimodal-ids-esp32')
    p.add_argument('--label-host', default='192.168.56.1')
    p.add_argument('--ssid', help='Deprecated; ignored. SYN uses routed IPv4, not Wi-Fi association.')
    p.add_argument('--attack-iface', default='eth0', help='Kali virtual NIC with a route to ESP32')
    p.add_argument('--port', default='COM3')
    p.add_argument('--out')
    p.add_argument('--run', action='store_true')
    a = p.parse_args(argv)
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', a.attack_iface):
        p.error('Invalid interface name')
    for value in (a.kali_host, a.label_host):
        if not ipaddress.IPv4Address(value).is_private:
            p.error('Private lab addresses required')
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_-]*', a.kali_user):
        p.error('Invalid SSH username')
    preflight(a)
    print('Preflight OK. No traffic generated.' if not a.run else 'Preflight OK; starting lab session.', flush=True)
    if not a.run:
        return 0
    # Controller files live outside the exclusive collector archive.
    token = uuid.uuid4().hex[:12]
    work = ROOT/'data'/('campaign_'+token)
    work.mkdir(parents=True, exist_ok=False)
    output = Path(a.out).resolve() if a.out else ROOT/'captures'/('syn_'+token)
    if output.exists():
        raise ValueError('Choose a new capture output directory')
    live, stop = work/'live.json', work/'stop'
    collector = remote = None
    report = {'dataset': str(output), 'result': 'incomplete', 'label_semantics': 'whole experiment interval including batch pauses'}
    # New process group prevents terminal Ctrl+C from abruptly killing the collector.
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    try:
        with (work/'collector.log').open('w', encoding='utf-8') as log, (work/'collector.err.log').open('w', encoding='utf-8') as err, \
             (work/'kali.log').open('wb') as remote_log, (work/'kali.err.log').open('wb') as remote_err:
            collector = subprocess.Popen([sys.executable, '-u', str(ROOT/'scripts/serial_collector.py'),
                '--port', a.port, '--baud', '921600', '--out', str(output), '--label', 'normal',
                '--label-bind', a.label_host, '--label-port', '9999', '--live-state', str(live),
                '--stop-file', str(stop), '--stats-interval', '1'], cwd=ROOT,
                stdout=log, stderr=err, creationflags=flags)
            print(f'Dataset: {output}\nCollector log: {work / "collector.log"}', flush=True)
            deadline = time.monotonic()+90
            state = None
            while time.monotonic() < deadline:
                state = read_live(live, collector)
                if state:
                    break
                time.sleep(1)
            if not state:
                raise RuntimeError('No fresh firmware IP/packets; flash IPv4 HELLO firmware first')
            target = str(ipaddress.IPv4Address(state['esp32_ip']))
            if not ipaddress.IPv4Address(target).is_private:
                raise ValueError('Refusing non-private target')
            report['target'] = target
            print(f'ESP32 target: {target}. Collecting 30 seconds normal baseline.', flush=True)
            for _ in range(30):
                if not read_live(live, collector):
                    raise RuntimeError('Capture lost freshness before experiment')
                time.sleep(1)
            state = read_live(live, collector)
            if not state or state['esp32_ip'] != target:
                raise RuntimeError('ESP32 address changed; restart session')
            cmd = ('cd '+shlex.quote(a.kali_project)+' && ( '+remote_env(a, target)+'; '
                   'sudo -n -E '+shlex.quote(a.kali_project+'/host/attacks/syn_flood.sh')+' )')
            print(f'Kali logs: {work / "kali.log"}, {work / "kali.err.log"}', flush=True)
            remote = subprocess.Popen(ssh_args(a, cmd), creationflags=flags,
                                      stdout=remote_log, stderr=remote_err)
            deadline = time.monotonic()+180
            while remote.poll() is None:
                if time.monotonic() > deadline:
                    raise RuntimeError('Remote timeout; verify Kali stopped before using archive')
                if not read_live(live, collector):
                    raise RuntimeError('Capture/IP lost during experiment; inspect incomplete archive')
                time.sleep(1)
            if remote.returncode:
                detail = log_tail(work/'kali.err.log') or log_tail(work/'kali.log') or 'No remote diagnostic output.'
                raise RuntimeError(f'Remote experiment failed: {remote.returncode}\n{detail}\nFull logs: {work}')
            verify_events(output/'dataset.sqlite3')
            print('START/STOP committed. Collecting 30 seconds recovery.', flush=True)
            for _ in range(30):
                if collector.poll() is not None:
                    raise RuntimeError('Collector exited during recovery')
                time.sleep(1)
            report['result'] = 'completed'
    except BaseException as exc:
        report['error'] = str(exc) or type(exc).__name__
        report['kali_stderr_tail'] = log_tail(work/'kali.err.log')
        report['collector_stderr_tail'] = log_tail(work/'collector.err.log')
        raise
    finally:
        if remote is not None and remote.poll() is None:
            # Do not claim STOP on behalf of a possibly still-running remote generator.
            remote.terminate()
            print('SSH interrupted. Kali has per-batch time limits; verify it stopped. Archive is incomplete.', flush=True)
        temporary = stop.with_suffix('.tmp')
        temporary.write_text('controller_stop' if report['result'] == 'completed' else 'campaign_incomplete', encoding='utf-8')
        temporary.replace(stop)
        if collector is not None:
            try:
                collector.wait(timeout=15)
                if collector.returncode:
                    report['result'] = 'incomplete'
            except subprocess.TimeoutExpired:
                report['result'] = 'incomplete'
                print('Collector did not close; not force-killing SQLite. Inspect process/logs.', flush=True)
        (work/'campaign.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'Campaign report: {work / "campaign.json"}', flush=True)
    if report['result'] != 'completed':
        raise RuntimeError('Campaign incomplete')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
