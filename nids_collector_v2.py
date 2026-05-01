import socket
import csv
import re
import select
from datetime import datetime
from collections import deque
import time

UDP_IP = "0.0.0.0"
LOG_PORT = 514
CONTROL_PORT = 9999

timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"nids_dataset_{timestamp_str}.csv"

# Regex pattern to extract RFC5424 structured data
regex = re.compile(r'\[meta@(?P<pen>[^ ]+) rssi="(?P<rssi>[^"]+)" snr="(?P<snr>[^"]+)" ipat="(?P<ipat>[^"]+)" seq="(?P<seq>[^"]+)" heap="(?P<heap>[^"]+)" uptime="(?P<uptime>[^"]+)"\]')

def start_receiver():
    current_label = 0  # 0: normal, 1: under attack
    attack_start_time = None
    
    # Create UDP socket for syslog messages
    log_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log_sock.bind((UDP_IP, LOG_PORT))
    log_sock.setblocking(False)  # 非阻塞模式
    
    # Create UDP socket for control signals
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctrl_sock.bind((UDP_IP, CONTROL_PORT))
    ctrl_sock.setblocking(False)  # 非阻塞模式
    
    print(f"✅ NIDS Collector Started")
    print(f"   📡 Listening for syslog on port {LOG_PORT}")
    print(f"   🎛️  Listening for control signals on port {CONTROL_PORT}")
    print(f"   💾 Saving to: {CSV_FILE}")
    
    # Track statistics
    normal_count = 0
    attack_count = 0
    
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["pen", "rssi", "snr", "ipat", "seq", "heap", "uptime", "label", "timestamp"])
        
        try:
            while True:
                # 使用select进行多路复用，避免完全阻塞
                readable, _, _ = select.select([log_sock, ctrl_sock], [], [], 0.1)
                
                # Check for control messages (START/STOP)
                if ctrl_sock in readable:
                    try:
                        msg, addr = ctrl_sock.recvfrom(1024)
                        status = msg.decode().strip()
                        
                        if status == "START":
                            current_label = 1
                            attack_start_time = datetime.now()
                            print(f"\n🚨 [ATTACK START] {attack_start_time.strftime('%H:%M:%S.%f')[:-3]} - Switching to ATTACK mode")
                        elif status == "STOP":
                            current_label = 0
                            duration = (datetime.now() - attack_start_time).total_seconds() if attack_start_time else 0
                            print(f"✋ [ATTACK STOP] - Switching to NORMAL mode (Duration: {duration:.2f}s)")
                            print(f"   📊 Captured {attack_count} attack packets in this round\n")
                            attack_count = 0
                    except Exception as e:
                        pass
                
                # Check for syslog messages
                if log_sock in readable:
                    try:
                        data, addr = log_sock.recvfrom(1024)
                        log_line = data.decode().strip()
                        log_time = datetime.now()
                        
                        match = regex.search(log_line)
                        if match:
                            d = match.groupdict()
                            row = [d["pen"], d["rssi"], d["snr"], d["ipat"], d["seq"], d["heap"], d["uptime"], current_label, log_time.isoformat()]
                            writer.writerow(row)
                            f.flush()
                            
                            # Update statistics and print
                            if current_label == 0:
                                normal_count += 1
                                status_indicator = "🟢"
                            else:
                                attack_count += 1
                                status_indicator = "🔴"
                            
                            print(f"{status_indicator} [{log_time.strftime('%H:%M:%S.%f')[:-3]}] "
                                  f"RSSI={d['rssi']:>4}dBm, SNR={d['snr']:>3}dB, "
                                  f"IPAT={d['ipat']:>6}us, SEQ={d['seq']:>5}, "
                                  f"HEAP={d['heap']:>6}B | Label: {current_label}")
                    except Exception as e:
                        pass
        
        except KeyboardInterrupt:
            print(f"\n\n⏹️  Collector stopped by user")
            print(f"   📈 Total packets: {normal_count + attack_count}")
            print(f"   ✅ Normal packets: {normal_count}")
            print(f"   ⚠️  Attack packets: {attack_count}")

if __name__ == "__main__":
    start_receiver()
