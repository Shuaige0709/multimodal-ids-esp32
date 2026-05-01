import socket
import csv
import re
from datetime import datetime

UDP_IP = "0.0.0.0"
LOG_PORT = 514
CONTROL_PORT = 9999  # optional control port for receiving START/STOP signals

timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"nids_dataset_{timestamp_str}.csv"

regrex = re.compile(r'\[meta@(?P<pen>[^ ]+) rssi="(?P<rssi>[^"]+)" snr="(?P<snr>[^"]+)" ipat="(?P<ipat>[^"]+)" seq="(?P<seq>[^"]+)" heap="(?P<heap>[^"]+)" uptime="(?P<uptime>[^"]+)"\]')

def start_receiver():
    current_label = 0       # 0: normal, 1: deauth attack
    log_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log_sock.bind((UDP_IP, LOG_PORT))

    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctrl_sock.bind((UDP_IP, CONTROL_PORT))
    ctrl_sock.setblocking(False)
    print(f"NIDS Collector Started, waiting for ESP32 on port {LOG_PORT}...")

    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["pen", "rssi", "snr", "ipat", "seq", "heap", "uptime", "label"])

        while True:
            try:
                msg, _ = ctrl_sock.recvfrom(1024)
                status = msg.decode().strip()
                if status == "START":
                    current_label = 1
                    print("Received START signal, switching to DEAUTH ATTACK mode")
                elif status == "STOP":
                    current_label = 0
                    print("Received STOP signal, switching to NORMAL mode")
            except:
                pass

            data, addr = log_sock.recvfrom(1024)
            log_line = data.decode().strip()

            match = regrex.search(log_line)
            if match:
                d = match.groupdict()
                writer.writerow([d["pen"], d["rssi"], d["snr"], d["ipat"], d["seq"], d["heap"], d["uptime"], current_label])
                print(f"Logged data from {addr}: {d} with label {current_label}")
                f.flush()  # ensure data is written to disk immediately

if __name__ == "__main__":
    start_receiver()