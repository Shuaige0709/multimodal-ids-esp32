# 租屋處怎麼收

Pi 上的 `nids_collector.py` **每一場都要開**。  
`serial_collector.py` **不在 Pi 上跑**。它接的是 Windows 上那條燒錄 USB 線，只有會把 ESP32 踢下線的攻擊才要多開這支。

每一種攻擊單獨一個 CSV：`正常 3 分鐘 → 攻擊 60–90 秒 → 正常 3 分鐘`。不要把好幾種攻擊錄在同一檔。

---

## 事先一次

1. `main/net_config.h` 的 SSID／密碼改成租屋處 AP，重新燒錄。`HIPS_ENABLE` 維持 0。
2. 路由器關掉 **client isolation / AP isolation / 訪客隔離**。ESP32、Pi、Kali 連同一個 AP。
3. Pi 只留一個 collector：`python3 host/collector/nids_collector.py`。Windows 不要再跑 `session_windows.ps1`。
4. Kali：`export NIDS_SSID=<跟韌體一樣>`，攻擊前 `./scripts/nids-sync.sh`。`sudo` 會清環境變數，攻擊用 `sudo -E`。
5. 等畫面上 `ARMED`（約 45 秒）之後才開始算那 3 分鐘正常。這段校準不要算進正常。

CSV 不要 `git add`。

---

## 要收哪些

| 順序 | 攻擊 | 腳本 | 誰收 | 這場在看什麼 |
|------|------|------|------|----------------|
| 1 | 正常 | 不打 | 只開 Pi collector | 租屋處閒置。先 15–20 分鐘，整檔都是 `NONE` |
| 2 | Deauth | `attack_deauth.sh` | **Pi + Windows USB** | 會踢下線。USB 用來補 Wi-Fi 斷掉的那段 |
| 3 | Disassoc | `attack_disassoc.sh` | **Pi + Windows USB** | 同樣會踢下線。至少兩場，各一個 CSV。Kali 要有 `python3-scapy` |
| 4 | Probe flood | `attack_probe_flood.sh` | 只開 Pi collector | 管理幀，通常不會把板子踢下線 |
| 5 | Evil twin | `attack_evil_twin.sh` | 只開 Pi collector | 看 `win_twin` / `win_rogue`。可選 |
| 6 | Auth flood | `attack_auth_flood.sh` | 只開 Pi collector | 只看租屋處 AP 上 `win_auth` 會不會升起。手機熱點上幾乎是平的 |
| 7 | ARP | `arpspoof.sh` | 只開 Pi collector | 只看 `gw_mac` 會不會變。手機熱點上看不到 |

先不要收 beacon flood，也不要用 `hping --flood` 當成正常流量。SYN 這輪不收。

---

## 隔離：要關掉，不是打開

「網路隔離」指的是路由器上的 **client isolation**。把它關掉。

關掉之後，同一顆 AP 上的裝置才看得到彼此。ARP 需要 Kali 用一般連線打到 ESP32；隔離開著，這條路會斷，`gw_flip` 會全程是 0。Auth、probe、deauth、disassoc、twin 是監聽注入，不靠這條路傳攻擊封包，但標籤 START/STOP 走的是 Kali 的有線／VMnet1 到 Pi，跟 Wi-Fi 隔離無關。

Auth 在手機熱點上看不見，是熱點本身幾乎不把 AUTH 幀放出來，不是因為少做了一層隔離。租屋處這顆 AP 關隔離後收一場即可，用來確認這裡看不看得到。

---

## 兩支 collector

| | 在哪跑 | 何時開 |
|--|--------|--------|
| `host/collector/nids_collector.py` | **Pi** | 每一場，從正常就開著，收到該場結束 |
| `scripts/serial_collector.py` | **Windows**（USB 接 ESP32） | 只有 deauth、disassoc。正常開始前就開，整場不要關 |

Deauth / disassoc 的 Windows 指令。可以先按 Build, Flash and Monitor。這支程式開 COM 埠前會關掉同一個埠上的 Monitor；若燒錄還沒結束，它會等，不會把燒錄砍掉：

```powershell
& "$env:USERPROFILE\.espressif\python_env\idf5.5_py3.11_env\Scripts\python.exe" `
  scripts/serial_collector.py --port COMx --standby --out data/raw/nids_serial.csv
```

Kali 在打這兩種之前：

```bash
export NIDS_SERIAL_LABEL_HOST=<Kali 連得到的那台 Windows IP>
export NIDS_SERIAL_LABEL_PORT=10000
```

Windows IP 多半是 VMnet1 的 `192.168.124.1`。Pi 的 collector 照舊收它自己的 9999，不用改。

Probe、twin、auth、ARP、純正常：**不要開 serial collector**，Pi 上的 `nids_collector.py` 就夠。

---

## 每場 Kali

會踢下線（deauth、disassoc）：

```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
# 正常 3 分鐘
sudo -E ./host/attacks/attack_deauth.sh
# 或 attack_disassoc.sh；加長：NIDS_DISASSOC_SEC=90
sudo -E ./host/attacks/prepare_wifi.sh managed
# 再正常 3 分鐘，等板子連回、Pi 又有持續列
```

Probe、auth、twin 也是先 `prepare_wifi.sh monitor`，再跑對應腳本。  
ARP 改走一般連線：`prepare_wifi.sh managed`，確認 Kali 已連上同一顆 AP，再 `arpspoof.sh`。

Pi 終端要看到 `ATTACK START` 和 `ATTACK STOP`。Deauth / disassoc 同時看 Windows 的 serial collector 有沒有印 START/STOP。

一場結束就在 Pi 上 Ctrl+C，存下 `data/raw/nids_dataset_*.csv`。下一場重新開 Pi collector。Deauth / disassoc 的 USB CSV 在 Windows 的 `--out` 那個檔，另外留著，不要和 Pi 的 CSV 混成一個。
