import csv
import re
import select
import socket
from datetime import datetime

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
YELLOW = "\033[33m"

UDP_IP = "0.0.0.0"
LOG_PORT = 514
CONTROL_PORT = 9999

timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"nids_dataset_{timestamp_str}.csv"

regex = re.compile(r'\[meta@(?P<pen>[^ ]+) rssi="(?P<rssi>[^"]+)" snr="(?P<snr>[^"]+)" ipat="(?P<ipat>[^"]+)" seq="(?P<seq>[^"]+)" heap="(?P<heap>[^"]+)" uptime="(?P<uptime>[^"]+)"\]')


def color_text(text, color):
    return f"{color}{text}{RESET}"


def format_status(label):
    if label == 0:
        return color_text("🟢 NORMAL", GREEN)
    return color_text("🔴 ATTACK", RED)


def start_receiver():
    current_label = 0
    current_state = "NORMAL"
    normal_count = 0
    attack_count = 0
    total_count = 0
    attack_start_time = None

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
        writer.writerow(["pen", "rssi", "snr", "ipat", "seq", "heap", "uptime", "label", "timestamp"])

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

                    status = msg.decode(errors="ignore").strip()
                    if status == "START":
                        current_label = 1
                        current_state = "ATTACK"
                        attack_start_time = datetime.now()
                        attack_count = 0
                        print(color_text("🚨 [ATTACK START] Switching to ATTACK mode", RED))
                    elif status == "STOP":
                        current_label = 0
                        current_state = "NORMAL"
                        duration = (datetime.now() - attack_start_time).total_seconds() if attack_start_time else 0
                        print(color_text(f"✋ [ATTACK STOP] Switching to NORMAL mode (Duration: {duration:.2f}s)", GREEN))
                        print(color_text(f"   📊 Attack packets in this round: {attack_count}", YELLOW))

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
                    writer.writerow([
                        d["pen"], d["rssi"], d["snr"], d["ipat"],
                        d["seq"], d["heap"], d["uptime"], current_label,
                        log_time.isoformat(),
                    ])
                    f.flush()

                    total_count += 1
                    if current_label == 0:
                        normal_count += 1
                        status_indicator = format_status(0)
                    else:
                        attack_count += 1
                        status_indicator = format_status(1)

                    print(
                        f"{status_indicator} [{log_time.strftime('%H:%M:%S.%f')[:-3]}] "
                        f"RSSI={d['rssi']:>4}dBm, SNR={d['snr']:>3}dB, "
                        f"IPAT={d['ipat']:>6}us, SEQ={d['seq']:>5}, "
                        f"HEAP={d['heap']:>6}B | Label: {current_label}"
                    )

if __name__ == "__main__":
    start_receiver()