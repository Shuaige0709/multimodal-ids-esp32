"""Read-only LAN dashboard fed by the serial collector; never opens a COM port."""
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import threading
import time


def number(row, key):
    try:
        return int(float(row.get(key) or 0))
    except (ValueError, TypeError):
        return 0


def alarm_types(row):
    """Follow display.c naming priority within RF; support simultaneous paths."""
    if number(row, 'attack') != 1:
        return []
    sources = number(row, 'm3src')
    names = []
    if sources & 4:
        names.append('ARP 身分異常')
    if sources & 2:
        names.append('Beacon Flood')
    if sources & 1 or not sources:
        if number(row, 'win_deauth') or number(row, 'deauth_tgt'):
            names.append('Deauth / Disassoc')
        elif number(row, 'win_twin') or number(row, 'win_rogue'):
            names.append('Evil Twin')
        elif number(row, 'win_probe'):
            names.append('Probe Flood')
        else:
            names.append('無線異常')
    return names or ['未分類告警']


class ProtectionState:
    def __init__(self):
        self.actions = deque(maxlen=100)
        self.invalidate()

    def invalidate(self):
        self.guard = {'mode': 'unknown', 'action': 'unknown', 'repairs': 0, 'err': 0}
        self.guard_at = self.probe_at = None
        self.target = None
        self.successes = self.failures = 0
        self.had_failure = False
        self.last_sent = None
        self.comm = 'unknown'
        self.sent = self.received = 0
        self.garp = {'action': 'unknown', 'count': 0, 'budget': 12}
        self.wireless = {'binding': 'unknown', 'pmf': 'unknown', 'bssid': None}
        self.wireless_at = None
        self.repair_events = self.rearm_events = 0
        self.pending_mismatch = self.pending_rearm = False

    def ingest(self, line, now, stamp):
        fields = dict(re.findall(r'(\w+)=([A-Za-z0-9:._+\-]+)', line))
        if '[ARP_GUARD_EVENT]' in line and fields.get('mismatch') == '1':
            self.pending_mismatch = True
        if '[WIFI_DEFENSE]' in line:
            self.wireless = {k: fields.get(k, 'unknown') for k in ('binding', 'pmf', 'bssid')}
            self.wireless_at = now
            self.garp['count'] = number(fields, 'garp')
            self.garp['budget'] = number(fields, 'budget')
        if '[ARP_GARP]' in line:
            self.garp = {'action': fields.get('action', 'unknown'),
                         'count': number(fields, 'count'), 'budget': number(fields, 'budget')}
            self.actions.appendleft({'action': 'garp_' + self.garp['action'],
                                     'mode': self.guard['mode'], 'time': stamp})
            # Sending a broadcast is not evidence that the peer accepted it.
            self.successes = self.failures = 0
            self.comm = 'checking'
        if '[ARP_GUARD]' in line:
            current = {'mode': fields.get('mode', 'unknown'),
                       'action': fields.get('action', 'unknown'),
                       'repairs': number(fields, 'repairs'), 'err': number(fields, 'err'),
                       'device_ip': fields.get('ip')}
            kind = current['action']
            if current['action'] == 'waiting' and self.guard['action'] == 'locked':
                self.pending_rearm = True
            if current['action'] == 'locked' and current['repairs'] > self.guard['repairs']:
                if self.pending_mismatch:
                    self.repair_events += 1
                    kind = 'repair'
                elif self.pending_rearm:
                    self.rearm_events += 1
                    kind = 'rearm'
                self.pending_mismatch = self.pending_rearm = False
            if current['repairs'] != self.guard['repairs'] or current['mode'] != self.guard['mode']:
                self.successes = self.failures = 0
                self.comm = 'checking'
            if current != self.guard:
                self.actions.appendleft({**current, 'kind': kind, 'time': stamp})
            self.guard, self.guard_at = current, now
        if '[ARP_PROBE]' in line:
            sent, received = number(fields, 'sent'), number(fields, 'received')
            if sent == self.last_sent and fields.get('result') != 'error':
                return
            if self.probe_at is not None and now - self.probe_at > 5:
                self.successes = self.failures = 0
                self.had_failure = False
            self.probe_at, self.target = now, fields.get('target')
            self.last_sent, self.sent, self.received = sent, sent, received
            if fields.get('result') == 'ok':
                self.successes += 1
                self.failures = 0
                self.comm = 'checking' if self.successes < 3 else 'reachable'
                if (self.successes >= 3 and self.had_failure and
                        self.guard['mode'] == 'on' and self.guard['action'] == 'locked' and
                        number(fields, 'repair') == self.guard['repairs']):
                    self.comm = 'recovered'
            elif fields.get('result') == 'timeout':
                self.failures += 1
                self.successes = 0
                if self.failures >= 2:
                    self.had_failure = True
                self.comm = 'failed' if self.failures >= 2 else 'checking'
            else:
                self.successes = self.failures = 0
                self.comm = 'error'

    def snapshot(self, now, serial_fresh):
        guard_fresh = serial_fresh and self.guard_at is not None and now - self.guard_at < 5
        probe_fresh = serial_fresh and self.probe_at is not None and now - self.probe_at < 5
        comm = self.comm if probe_fresh and guard_fresh else 'unknown'
        if comm == 'recovered' and (self.guard['action'] != 'locked' or self.guard['err']):
            comm = 'reachable'
        return {**self.guard, 'fresh': guard_fresh, 'target': self.target,
                'repair_events': self.repair_events, 'rearm_events': self.rearm_events,
                'communication': comm,
                'sent': self.sent, 'received': self.received,
                'actions': list(self.actions),
                'garp': dict(self.garp), 'wireless': dict(self.wireless),
                'wireless_fresh': serial_fresh and self.wireless_at is not None
                                  and now - self.wireless_at < 5,
                'success_streak': self.successes if probe_fresh else 0}


def display_events(events, outages, stamp):
    """Group correlated RF records for presentation; preserve raw events intact.

    A continuous measured outage plus a Deauth observation is required. ARP,
    Beacon and Twin records are never absorbed. No attack labels are consulted.
    """
    result = [dict(e) for e in events]
    for outage in outages:
        if outage['outcome'] == 'interrupted':
            continue
        left = datetime.fromisoformat(outage['start']).timestamp() - 2
        right = datetime.fromisoformat(outage['end'] or stamp).timestamp()
        members = [e for e in result
                   if e['type'] in ('Deauth / Disassoc', 'Probe Flood', '無線異常')
                   and left <= datetime.fromisoformat(e['start']).timestamp()
                   and datetime.fromisoformat(e['last']).timestamp() <= right]
        if not any(e['type'] == 'Deauth / Disassoc' for e in members):
            continue
        first = min(members, key=lambda e: e['start'])
        last = max(members, key=lambda e: e['last'])
        grouped = {**first, 'type': 'Deauth / Disassoc', 'last': last['last'],
                   'duration': round((datetime.fromisoformat(last['last']) -
                                      datetime.fromisoformat(first['start'])).total_seconds(), 1),
                   'windows': sum(e['windows'] for e in members),
                   'active': any(e['active'] for e in members),
                   'source_ids': [e['id'] for e in members],
                   'observed_types': sorted({e['type'] for e in members}),
                   'outage_id': outage['id']}
        result = [e for e in result if e not in members] + [grouped]
    return sorted(result, key=lambda e: e['start'], reverse=True)


class DashboardState:
    def __init__(self, clock=time.monotonic, wall_clock=datetime.now):
        self.clock = clock
        self.wall_clock = wall_clock
        self.lock = threading.Lock()
        self.serial = False
        self.error = None
        self.last_line = None
        self.last_window = None
        self.wifi = 'unknown'
        self.wifi_at = None
        self.ip = None
        self.latest = {}
        self.events = deque(maxlen=100)
        self.sequence = 0
        self.active = {}
        self.current_types = []
        self.previous_uptime = None
        self.started = self.wall_clock().isoformat(timespec='seconds')
        self.last_link = None
        self.link_phase = 'unknown'
        self.outages = deque(maxlen=100)
        self.outage = None
        self.outage_sequence = 0
        self.recovered_at = None
        self.protection = ProtectionState()
        self.guard_event_at = None

    def _interrupt_link(self, now, stamp):
        self.protection.invalidate()
        self.guard_event_at = None
        if self.outage:
            self.outage['outcome'] = 'interrupted'
            self.outage['end'] = stamp
            self.outage['_end'] = now
            self.outage = None
        self.link_phase = 'unknown'
        self.last_link = None
        self.recovered_at = None

    def _alarm(self, name, now, stamp, window=True):
        event = self.active.get(name)
        if event is None or now - event['_last'] > 2:
            self.sequence += 1
            event = {'id': self.sequence, 'type': name, 'start': stamp,
                     'last': stamp, 'windows': 0, 'wifi': self.wifi,
                     '_start': now, '_last': now}
            self.events.appendleft(event)
            self.active[name] = event
        event['last'], event['_last'] = stamp, now
        event['windows'] += int(window)
        event['wifi'] = self.wifi

    def _link(self, up, now, stamp, explicit=False, attempt=False):
        if self.last_link is not None and now - self.last_link >= 5 and self.outage:
            self._interrupt_link(now, stamp)
        self.last_link = now
        self.wifi_at = stamp
        if attempt and self.wifi == 'unknown' and self.outage is None:
            self.link_phase = 'connecting'
            return
        if up:
            self.wifi = 'up'
            if self.outage:
                self.outage['outcome'] = 'recovered'
                self.outage['end'] = stamp
                self.outage['_end'] = now
                self.outage = None
                self.recovered_at = now
            self.link_phase = 'up'
        else:
            self.wifi, self.ip = 'down', None
            if self.outage is None:
                self.outage_sequence += 1
                self.outage = {'id': self.outage_sequence, 'start': stamp,
                               'end': None, 'outcome': 'open', 'attempts': 0,
                               'start_known': explicit, '_start': now, '_end': None}
                self.outages.appendleft(self.outage)
                self.link_phase = 'down'
            if attempt:
                self.outage['attempts'] += 1
                self.link_phase = 'reconnecting'

    def transport(self, connected, error=None):
        with self.lock:
            self._interrupt_link(self.clock(), self.wall_clock().isoformat(timespec='seconds'))
            self.serial = connected
            self.error = str(error) if error else None
            self.active.clear()
            self.current_types = []
            if connected:
                self.wifi = 'unknown'
                self.ip = None
                self.last_line = self.last_window = None

    def ingest(self, line, row=None):
        now = self.clock()
        stamp = self.wall_clock().isoformat(timespec='seconds')
        with self.lock:
            self.last_line = now
            if 'rst:0x' in line or 'ESP-ROM:' in line:
                self._interrupt_link(now, stamp)
                self.wifi = 'unknown'
                self.ip = None
                self.active.clear()
                self.current_types = []
                self.last_window = None
                self.previous_uptime = None
            if 'WiFi disconnected' in line:
                self._link(False, now, stamp, explicit=True)
            elif 'WiFi connected; resuming' in line or 'Got IP:' in line:
                self._link(True, now, stamp)
                match = re.search(r'Got IP:\s*([\d.]+)', line)
                if match:
                    self.ip = match[1]
            link = re.search(r'\[NIDS_LINK\] connected=([01])\b', line)
            if link:
                self._link(link[1] == '1', now, stamp)
            if '[NIDS_RECONNECT] attempt' in line:
                self._link(False, now, stamp, attempt=True)
            self.protection.ingest(line, now, stamp)
            if '[ARP_GUARD_EVENT] mismatch=1' in line:
                self.guard_event_at = now
                self._alarm('ARP 身分異常', now, stamp, window=False)
            if row is None:
                return
            uptime = number(row, 'uptime')
            if self.previous_uptime is not None and uptime < self.previous_uptime - 5000:
                self._interrupt_link(now, stamp)
                self.active.clear()
                self.wifi, self.ip = 'unknown', None
            self.previous_uptime = uptime
            self.last_window = now
            self.latest = {key: row.get(key) for key in (
                'channel', 'win_pkts', 'host_mac', 'uptime', 'calib', 'attack')}
            names = alarm_types(row)
            self.current_types = names
            for name in names:
                self._alarm(name, now, stamp)

    def snapshot(self):
        now = self.clock()
        with self.lock:
            age = None if self.last_line is None else max(0, now - self.last_line)
            window_age = None if self.last_window is None else max(0, now - self.last_window)
            fresh = self.serial and age is not None and age < 5
            model_fresh = (fresh and window_age is not None and window_age < 2
                           and self.latest.get('attack') in ('0', '1', 0, 1))
            active = [name for name, e in self.active.items()
                      if fresh and now - e['_last'] < 2 and (
                          (name in self.current_types and model_fresh) or
                          (name == 'ARP 身分異常' and self.guard_event_at is not None
                           and now - self.guard_event_at < 2))]
            state = ('offline' if not self.serial else 'waiting' if age is None
                     else 'stale' if not fresh else 'alert' if active
                     else 'waiting' if not model_fresh else 'monitoring')
            events = []
            for e in self.events:
                item = {k: v for k, v in e.items() if not k.startswith('_')}
                item['duration'] = round(e['_last'] - e['_start'], 1)
                item['active'] = e['type'] in active and self.active.get(e['type']) is e
                events.append(item)
            link_fresh = (fresh and self.last_link is not None
                          and now - self.last_link < 5)
            connection_phase = self.link_phase if link_fresh else 'unknown'
            if (connection_phase == 'up' and self.recovered_at is not None
                    and now - self.recovered_at < 8):
                connection_phase = 'recovered'
            outages = []
            for e in self.outages:
                item = {k: v for k, v in e.items() if not k.startswith('_')}
                # Missing UART cannot be counted as a measured recovery.
                end = e['_end'] if e['_end'] is not None else (
                    now if link_fresh else self.last_link or e['_start'])
                item['duration'] = (round(max(0, end - e['_start']), 1)
                                    if e['outcome'] != 'interrupted' else None)
                outages.append(item)
            return {'state': state, 'serial': self.serial, 'age': age,
                    'window_age': window_age, 'wifi': self.wifi,
                    'wifi_fresh': link_fresh, 'wifi_at': self.wifi_at, 'ip': self.ip,
                    'connection': {'phase': connection_phase, 'outages': outages,
                                   'total': self.outage_sequence, 'fresh': link_fresh},
                    'types': active, 'latest': dict(self.latest), 'events': events,
                    'display_events': display_events(events, outages, self.wall_clock().isoformat()),
                    'protection': self.protection.snapshot(now, fresh),
                    'total': self.sequence, 'error': self.error, 'started': self.started}


def save_dashboard_snapshot(state, path, metadata=None):
    """Atomically save an observation snapshot without mutating the live state."""
    snapshot = state.snapshot()
    snapshot['export'] = {'saved_at': datetime.now().isoformat(timespec='seconds'),
                          **(metadata or {})}
    target = Path(path)
    temporary = target.with_name(target.name + '.tmp')
    temporary.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(target)
    return snapshot


class DashboardHTTPServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR can let an old replay and a live collector share
    # one port. A successful bind must identify exactly one dashboard source.
    allow_reuse_address = not hasattr(socket, 'SO_EXCLUSIVEADDRUSE')

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def start_dashboard(state, host='0.0.0.0', port=8080):
    root = Path(__file__).with_name('demo_web')
    html = root.joinpath('index.html').read_bytes()
    assets = {('/assets/' + name): (root.joinpath('assets', name).read_bytes(), mime)
              for name, mime in (
                  ('dashboard.css', 'text/css; charset=utf-8'),
                  ('dashboard.js', 'text/javascript; charset=utf-8'),
                  ('watch-effects.js', 'text/javascript; charset=utf-8'),
                  ('shader-engine.js', 'text/javascript; charset=utf-8'),
                  ('shaders-LICENSE.txt', 'text/plain; charset=utf-8'),
                  ('Geist.woff2', 'font/woff2'),
                  ('favicon.svg', 'image/svg+xml'),
                  ('Geist-LICENSE.txt', 'text/plain; charset=utf-8'))}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split('?', 1)[0]
            status = 200
            if path == '/api/status':
                payload = json.dumps(state.snapshot(), ensure_ascii=False).encode('utf-8')
                mime = 'application/json; charset=utf-8'
            elif path == '/':
                payload, mime = html, 'text/html; charset=utf-8'
            elif path in assets:
                payload, mime = assets[path]
            else:
                status = 404
                payload = ('<!doctype html><html lang="zh-Hant"><meta charset="utf-8">'
                           '<meta name="viewport" content="width=device-width,initial-scale=1">'
                           '<title>找不到頁面 · 燕子守望</title>'
                           '<link rel="stylesheet" href="/assets/dashboard.css">'
                           '<main class="shell"><h1 class="heading-5">找不到這個頁面</h1>'
                           '<p class="body-3"><a href="/">回到燕子守望</a></p></main></html>').encode('utf-8')
                mime = 'text/html; charset=utf-8'
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = DashboardHTTPServer((host, port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
