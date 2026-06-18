#!/bin/bash
# 1. 準備監聽模式 (wlan0)
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo iwconfig wlan0mon channel 11

# 2. 準備通訊管道 (eth0 -> VMnet1)
# 確保 eth0 走 Host-Only 路徑連接 Windows 主機
sudo ip addr flush dev eth0
sudo ip addr add 192.168.220.50/24 dev eth0
sudo ip link set eth0 up

echo "==========================================="
echo " 攻擊網卡：wlan0mon (Channel 11)"
echo " 通訊網卡：eth0 (IP: 192.168.220.50)"
echo " 目標電腦：192.168.220.2 (Windows Host)"
echo "==========================================="
echo
echo "=== TO RECOVER ==="
echo "sudo airmon-ng stop wlan0mon"
echo "sudo systemctl restart NetworkManager"