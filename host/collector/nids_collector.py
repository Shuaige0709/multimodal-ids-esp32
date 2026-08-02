import csv
import os
import re
import select
import socket
import json
import sys
import threading
import time
from datetime import datetime, timedelta

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
YELLOW = "\033[33m"

UDP_IP = "0.0.0.0"
LOG_PORT = 1514
CONTROL_PORT = 9999

# --- Auto-discovery: broadcast a beacon so the ESP32 finds us without a hard-coded IP ---
DISCOVERY_PORT = 5005
DISCOVERY_MAGIC = "NIDS_DISCOVERY"
BEACON_INTERVAL_SEC = 1.5

# Allow running as `python host/collector/nids_collector.py`
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_RAW, LIVE_STATE_FILE, ensure_data_dirs  # noqa: E402

ensure_data_dirs()
timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_FILE = os.path.join(DATA_RAW, f"nids_dataset_{timestamp_str}.csv")

regex = re.compile(
    r'\[meta@(?P<pen>[^ ]+) '
    r'subtype="(?P<subtype>[^"]*)" '
    r'rssi="(?P<rssi>[^"]+)" '
    r'snr="(?P<snr>[^"]+)" '
    r'ipat="(?P<ipat>[^"]+)" '
    r'seq="(?P<seq>[^"]+)" '
    r'heap="(?P<heap>[^"]+)" '
    r'minheap="(?P<minheap>[^"]+)" '
    r'uptime="(?P<uptime>[^"]+)" '
    r'reconn="(?P<reconn>[^"]+)" '
    r'qpeak="(?P<qpeak>[^"]+)" '
    r'udpfail="(?P<udpfail>[^"]+)" '
    r'backlog="(?P<backlog>[^"]+)" '
    r'dropped="(?P<dropped>[^"]+)"'
    r'(?: host_mac="(?P<host_mac>[^"]+)")?'
    r'(?: attack="(?P<attack>[^"]+)")?'
    r'(?: deauth_tgt="(?P<deauth_tgt>[^"]+)")?'
    r'(?: seq_jump="(?P<seq_jump>[^"]+)")?'
    r'(?: ap_bssid="(?P<ap_bssid>[^"]+)")?'
    r'(?: channel="(?P<channel>[^"]+)")?'
    r'\]'
)

_META_KEYS = (
    "pen", "subtype", "rssi", "snr", "ipat", "seq", "heap", "minheap",
    "uptime", "reconn", "qpeak", "udpfail", "backlog", "dropped",
    "host_mac", "attack", "deauth_tgt", "seq_jump", "ap_bssid", "channel",
)
_KV_RE = re.compile(r'([a-z_]+)="([^"]*)"')
_PEN_RE = re.compile(r'\[meta@(\S+)')


def parse_syslog_meta(log_line):
    """Full RFC5424 meta match, or best-effort KV parse for truncated (old 256B) firmware."""
    match = regex.search(log_line)
    if match:
        return match.groupdict(), False

    pairs = dict(_KV_RE.findall(log_line))
    if "rssi" not in pairs or "heap" not in pairs:
        return None, False
    pen_m = _PEN_RE.search(log_line)
    if pen_m:
        pairs["pen"] = pen_m.group(1)
    str_keys = ("subtype", "host_mac", "attack", "ap_bssid", "channel")
    for key in _META_KEYS:
        pairs.setdefault(key, "" if key in str_keys else "0")
    return pairs, True


def color_text(text, color):
    return f"{color}{text}{RESET}"


def get_local_ip_towards(peer_ip):
    """Best-effort discovery of the local IP that would be used to reach peer_ip."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((peer_ip, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def list_local_ipv4():
    """Collect non-loopback IPv4 addresses on this host (best-effort)."""
    found = []

    def _add(ip):
        if ip and not ip.startswith("127.") and ip not in found:
            found.append(ip)

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            _add(info[4][0])
    except OSError:
        pass
    # Probe a few destinations to surface interface addresses (VMnet1, NAT, Wi-Fi, …)
    for peer in ("8.8.8.8", "192.168.124.2", "192.168.220.50", "192.168.1.1"):
        _add(get_local_ip_towards(peer))
    # Linux/Pi: hostname -I lists every interface (wlan0 + eth0), which getaddrinfo often misses
    try:
        import subprocess
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
        for tok in out.split():
            _add(tok)
    except (OSError, subprocess.SubprocessError):
        pass
    return found


def guess_label_host(esp32_ip=None):
    """
    IP that Kali should send START/STOP labels to.

    Often different from the Wi-Fi IP used for ESP32 syslog:
      - Windows collector: VMnet1 host-only (e.g. 192.168.124.1)
      - Pi collector: usually the Pi address Kali can route to
    Override with NIDS_LABEL_ADVERTISE (or NIDS_LABEL_HOST) if guessing is wrong.
    """
    forced = os.environ.get("NIDS_LABEL_ADVERTISE") or os.environ.get("NIDS_LABEL_HOST")
    if forced:
        return forced

    syslog_ip = get_local_ip_towards(esp32_ip) if esp32_ip else None
    esp_prefix = esp32_ip.rsplit(".", 1)[0] if esp32_ip else None
    candidates = list_local_ipv4()

    # Prefer an address NOT on the ESP32 Wi-Fi subnet (host-only / lab LAN for Kali).
    for ip in candidates:
        if ip.startswith("169.254."):
            continue
        if esp_prefix and ip.rsplit(".", 1)[0] == esp_prefix:
            continue
        if syslog_ip and ip == syslog_ip:
            continue
        return ip

    if syslog_ip:
        return syslog_ip
    if candidates:
        return candidates[0]
    return None


def write_live_state(esp32_ip=None, esp32_mac=None, ap_bssid=None, channel=None):
    """Persist ESP32 + collector endpoints so attack scripts need no hard-coded IPs."""
    syslog_ip = get_local_ip_towards(esp32_ip) if esp32_ip else None
    label_host = guess_label_host(esp32_ip)
    # Preserve previously known AP fields if this call omits them
    prev = {}
    try:
        if os.path.isfile(LIVE_STATE_FILE):
            with open(LIVE_STATE_FILE, encoding="utf-8") as fh:
                prev = json.load(fh)
    except (OSError, ValueError):
        prev = {}
    state = {
        "esp32_ip": esp32_ip,
        "esp32_mac": esp32_mac,
        # IP ESP32 uses to reach us (hotspot / discovery path)
        "collector_ip": syslog_ip or label_host,
        # IP Kali should use for START/STOP (often VMnet1 host-only on Windows)
        "label_host": label_host,
        "ap_bssid": ap_bssid or prev.get("ap_bssid"),
        "channel": channel if channel is not None else prev.get("channel"),
        "log_port": LOG_PORT,
        "control_port": CONTROL_PORT,
        "updated": datetime.now().isoformat(),
    }
    tmp = LIVE_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, LIVE_STATE_FILE)
    return state


def _discovery_targets():
    """
    Broadcast destinations for collector discovery.

    Global 255.255.255.255 only goes out the default route interface. On a Pi
    that is often eth0 while ESP32 is on wlan0 — so also send per-subnet
    directed broadcasts (x.x.x.255) for every local IPv4 we can see.
    """
    targets = [("255.255.255.255", DISCOVERY_PORT)]
    for ip in list_local_ipv4():
        parts = ip.split(".")
        if len(parts) == 4 and not ip.startswith("169.254."):
            bcast = ".".join(parts[:3] + ["255"])
            pair = (bcast, DISCOVERY_PORT)
            if pair not in targets:
                targets.append(pair)
    return targets


def beacon_broadcaster(stop_event):
    """Periodically broadcast a discovery beacon so the ESP32 learns our IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    payload = f"{DISCOVERY_MAGIC} v1 log={LOG_PORT}".encode()
    local_ips = list_local_ipv4() or ["(none found)"]
    print(color_text(
        f"   📣 Broadcasting discovery beacon on UDP :{DISCOVERY_PORT} every {BEACON_INTERVAL_SEC}s",
        CYAN))
    print(color_text(f"   🌐 Local IPv4s: {', '.join(local_ips)}", CYAN))
    while not stop_event.is_set():
        for host, port in _discovery_targets():
            try:
                sock.sendto(payload, (host, port))
            except OSError as e:
                print(color_text(f"   ⚠️  beacon → {host}:{port} failed: {e}", YELLOW))
        stop_event.wait(BEACON_INTERVAL_SEC)
    sock.close()


def format_status(label, attack_type="NONE"):
    if label == 0:
        return color_text("🟢 NORMAL", GREEN)
    return color_text(f"🔴 ATTACK ({attack_type})", RED)


def start_receiver():
    current_label = 0
    current_state = "NORMAL"
    current_attack_type = "NONE"
    normal_count = 0
    attack_count = 0
    total_count = 0
    attack_start_time = None

    # Track historical attack intervals and ESP32 time alignment
    attack_intervals = [] # list of {"start": datetime, "end": datetime, "type": str}
    current_attack = None # current ongoing attack details {"start": datetime, "type": str}
    min_offset = None     # Estimated base offset (boot time) of the ESP32 in collector's clock
    last_uptime_sec = 0.0

    # Live ESP32 identity tracking (for auto-discovery / live_state.json)
    last_live_esp32 = (None, None, None, None)  # (ip, mac, ap_bssid, channel)

    # Start the discovery beacon so the ESP32 can find us with no hard-coded IP
    stop_event = threading.Event()
    beacon_thread = threading.Thread(target=beacon_broadcaster, args=(stop_event,), daemon=True)
    beacon_thread.start()

    log_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log_sock.bind((UDP_IP, LOG_PORT))
    log_sock.setblocking(False)

    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctrl_sock.bind((UDP_IP, CONTROL_PORT))
    ctrl_sock.setblocking(False)

    print(color_text("✅ NIDS Collector Started", CYAN))
    print(f"   📡 Listening for syslog on port {LOG_PORT}")
    print(f"   🎛️  Listening for control signals on port {CONTROL_PORT}")
    print(f"   💾 Saving to: {CSV_FILE}")

    # Advertise label_host immediately so Kali can read live_state before ESP32 appears
    boot_state = write_live_state(None, None)
    print(color_text(
        f"   🏷️  label_host={boot_state.get('label_host')} "
        f"(Kali START/STOP → this IP:{CONTROL_PORT}; override with NIDS_LABEL_ADVERTISE)",
        CYAN))
    print(color_text(
        "   ⏳ Waiting for ESP32 syslog… (idle is normal until discovery succeeds)",
        YELLOW))

    last_idle_hint = time.time()

    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "pen", "subtype", "rssi", "snr", "ipat", "seq", "heap", "minheap",
            "uptime", "reconn", "qpeak", "udpfail", "backlog", "dropped",
            "host_mac", "pred_attack", "deauth_tgt", "seq_jump",
            "ap_bssid", "channel", "label", "attack_type", "timestamp"
        ])

        while True:
            readable, _, _ = select.select([log_sock, ctrl_sock], [], [], 0.1)

            if ctrl_sock in readable:
                while True:
                    try:
                        msg, _ = ctrl_sock.recvfrom(1024)
                    except BlockingIOError:
                        break
                    except Exception:
                        break

                    raw_msg = msg.decode(errors="ignore").strip()
                    
                    try:
                        # 解析從 Kali 傳過來的進階 JSON 標籤
                        label_data = json.loads(raw_msg)
                        status = label_data.get("status")
                        attack_type = label_data.get("attack_type", "UNKNOWN")
                        
                        if status == "START":
                            current_label = 1
                            current_attack_type = attack_type
                            attack_start_time = datetime.now()
                            current_attack = {"start": attack_start_time, "type": current_attack_type}
                            attack_count = 0
                            print(color_text(f"🚨 [ATTACK START] Switching to {current_attack_type} mode", RED))
                            
                        elif status == "STOP":
                            stop_time = datetime.now()
                            duration = (stop_time - attack_start_time).total_seconds() if attack_start_time else 0
                            print(color_text(f"✋ [ATTACK STOP] {current_attack_type} finished (Duration: {duration:.2f}s)", GREEN))
                            print(color_text(f"   📊 Over-the-air packets in this round: {attack_count}", YELLOW))
                            
                            if current_attack is not None:
                                current_attack["end"] = stop_time
                                attack_intervals.append(current_attack)
                                current_attack = None

                            # 重設為正常狀態
                            current_label = 0
                            current_attack_type = "NONE"
                            
                    except json.JSONDecodeError:
                        # 兼容舊版純文字標籤傳輸
                        if raw_msg == "START":
                            current_label = 1
                            current_attack_type = "GENERIC_ATTACK"
                            attack_start_time = datetime.now()
                            current_attack = {"start": attack_start_time, "type": current_attack_type}
                            print(color_text("🚨 [ATTACK START] Generic mode enabled", RED))
                        elif raw_msg == "STOP":
                            stop_time = datetime.now()
                            if current_attack is not None:
                                current_attack["end"] = stop_time
                                attack_intervals.append(current_attack)
                                current_attack = None
                            current_label = 0
                            current_attack_type = "NONE"
                            print(color_text("✋ [ATTACK STOP] Generic mode disabled", GREEN))

            if log_sock in readable:
                while True:
                    try:
                        data, addr = log_sock.recvfrom(1024)
                    except BlockingIOError:
                        break
                    except Exception:
                        break

                    log_line = data.decode(errors="ignore").strip()
                    log_time = datetime.now()

                    d, truncated = parse_syslog_meta(log_line)
                    if not d:
                        print(color_text(
                            f"   ⚠️  syslog parse miss from {addr[0]} "
                            f"({len(data)}B): {log_line[:160]}",
                            YELLOW))
                        continue
                    if truncated and total_count < 3:
                        print(color_text(
                            f"   ⚠️  truncated syslog ({len(data)}B) from {addr[0]} — "
                            f"flash firmware with 512B buffer for full fields",
                            YELLOW))

                    # Record the ESP32's live IP/MAC/AP for attack scripts.
                    esp32_ip = addr[0]
                    esp32_mac = d.get("host_mac")
                    ap_bssid = d.get("ap_bssid") or None
                    channel = d.get("channel") or None
                    live_key = (esp32_ip, esp32_mac, ap_bssid, channel)
                    if live_key != last_live_esp32:
                        state = write_live_state(esp32_ip, esp32_mac, ap_bssid, channel)
                        last_live_esp32 = live_key
                        print(color_text(
                            f"   🛰️  ESP32 live at {esp32_ip} (mac={esp32_mac}); "
                            f"AP={state.get('ap_bssid')} ch={state.get('channel')}; "
                            f"label_host={state.get('label_host')}; "
                            f"wrote {os.path.basename(LIVE_STATE_FILE)}",
                            CYAN))

                    # Compute generation time of the syslog on ESP32
                    try:
                        uptime_sec = float(d["uptime"]) / 1000.0
                    except (ValueError, TypeError):
                        uptime_sec = 0.0

                    offset = log_time - timedelta(seconds=uptime_sec)
                    if uptime_sec < last_uptime_sec - 5.0 or min_offset is None:
                        min_offset = offset
                        print(color_text("🔄 ESP32 reset or new boot detected. Syncing base offset.", YELLOW))
                    elif offset < min_offset:
                        min_offset = offset

                    last_uptime_sec = uptime_sec
                    gen_time = min_offset + timedelta(seconds=uptime_sec)

                    # Check if packet was generated within any attack period
                    packet_label = 0
                    packet_attack_type = "NONE"

                    # 1. Finished attacks
                    for interval in attack_intervals:
                        if interval["start"] <= gen_time <= interval["end"]:
                            packet_label = 1
                            packet_attack_type = interval["type"]
                            break

                    # 2. Ongoing attack
                    if packet_label == 0 and current_attack is not None:
                        if gen_time >= current_attack["start"]:
                            packet_label = 1
                            packet_attack_type = current_attack["type"]

                    writer.writerow([
                        d["pen"], d.get("subtype", ""), d["rssi"], d["snr"], d["ipat"],
                        d["seq"], d["heap"], d["minheap"], d["uptime"],
                        d["reconn"], d["qpeak"], d["udpfail"], d["backlog"],
                        d["dropped"], d.get("host_mac", ""), d.get("attack", ""),
                        d.get("deauth_tgt", "0"), d.get("seq_jump", "0"),
                        d.get("ap_bssid", ""), d.get("channel", ""),
                        packet_label, packet_attack_type, gen_time.isoformat(),
                    ])
                    f.flush()

                    total_count += 1
                    if packet_label == 0:
                        normal_count += 1
                        status_indicator = format_status(0, "NONE")
                    else:
                        attack_count += 1
                        status_indicator = format_status(1, packet_attack_type)

                    print(
                        f"{status_indicator} [{gen_time.strftime('%H:%M:%S.%f')[:-3]}] (Recv: {log_time.strftime('%H:%M:%S.%f')[:-3]}) "
                        f"RSSI={d['rssi']:>4}dBm, SNR={d['snr']:>3}dB, "
                        f"IPAT={d['ipat']:>6}us, HEAP={d['heap']:>6}B | Type: {packet_attack_type}"
                    )


            if total_count == 0 and (time.time() - last_idle_hint) >= 15:
                last_idle_hint = time.time()
                print(color_text(
                    "   ⏳ Still no ESP32 syslog. On monitor look for "
                    "'Discovered collector' or 'Waiting for collector beacon'. "
                    "Pi + ESP32 must share the same Wi-Fi (SSID in net_config.h).",
                    YELLOW))

if __name__ == "__main__":
    start_receiver()