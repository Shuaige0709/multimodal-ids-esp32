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
    r'(?: host_mac="(?P<host_mac>[^"]+)")?'   # optional (newer firmware)
    r'(?: attack="(?P<attack>[^"]+)")?'       # optional on-device inference result
    r'\]'
)


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


def write_live_state(esp32_ip, esp32_mac):
    """Persist the ESP32's current IP/MAC so attack scripts never need hard-coded IPs."""
    state = {
        "esp32_ip": esp32_ip,
        "esp32_mac": esp32_mac,
        "collector_ip": get_local_ip_towards(esp32_ip) if esp32_ip else None,
        "log_port": LOG_PORT,
        "control_port": CONTROL_PORT,
        "updated": datetime.now().isoformat(),
    }
    tmp = LIVE_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, LIVE_STATE_FILE)
    return state


def beacon_broadcaster(stop_event):
    """Periodically broadcast a discovery beacon so the ESP32 learns our IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    payload = f"{DISCOVERY_MAGIC} v1 log={LOG_PORT}".encode()
    print(color_text(f"   📣 Broadcasting discovery beacon on UDP :{DISCOVERY_PORT} every {BEACON_INTERVAL_SEC}s", CYAN))
    while not stop_event.is_set():
        try:
            sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
        except OSError as e:
            print(color_text(f"   ⚠️  beacon send failed: {e}", YELLOW))
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
    last_live_esp32 = (None, None)  # (ip, mac)

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

    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "pen", "subtype", "rssi", "snr", "ipat", "seq", "heap", "minheap",
            "uptime", "reconn", "qpeak", "udpfail", "backlog", "dropped",
            "host_mac", "pred_attack", "label", "attack_type", "timestamp"
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

                    match = regex.search(log_line)
                    if not match:
                        continue

                    d = match.groupdict()

                    # Record the ESP32's live IP (packet source) + MAC (from syslog) for
                    # the attack scripts. Written only when it changes.
                    esp32_ip = addr[0]
                    esp32_mac = d.get("host_mac")
                    if (esp32_ip, esp32_mac) != last_live_esp32:
                        state = write_live_state(esp32_ip, esp32_mac)
                        last_live_esp32 = (esp32_ip, esp32_mac)
                        print(color_text(
                            f"   🛰️  ESP32 live at {esp32_ip} (mac={esp32_mac}); wrote {os.path.basename(LIVE_STATE_FILE)}",
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

if __name__ == "__main__":
    start_receiver()