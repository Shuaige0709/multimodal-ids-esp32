# 租屋處這輪要收什麼

這一輪只收下面這些。每一場單獨一個檔，不要把好幾種攻擊錄在一起。


| 順序  | 這一場                | 誰在錄                  | 檔案                                                     |
| --- | ------------------ | -------------------- | ------------------------------------------------------ |
| 1   | 什麼都不打，15–20 分鐘     | 只開 Pi                | Pi 自動存 `data/raw/nids_dataset_日期時間.csv`，整檔都是正常         |
| 2   | Deauth，約 60 秒      | Pi，再加上 Windows 的 USB | Pi 一個 CSV；Windows 另存 `data/raw/nids_serial_deauth.csv` |
| 3   | Disassoc，約 90 秒    | 同上，Pi + USB          | 換新檔名。這一輪要收兩場                                           |
| 4   | Disassoc，再一場       | 同上                   | 再換一個檔名，不要覆蓋上一場                                         |
| 5   | Probe flood，約 45 秒 | 只開 Pi                | 通常不會把板子踢下線                                             |
| 6   | Evil twin，約 60 秒   | 只開 Pi                | 可做可不做。看畫面上有沒有第二個同名熱點                                   |
| 7   | Auth flood，約 60 秒  | 只開 Pi                | 看這顆 AP 會不會出現大量認證幀                                      |
| 8   | ARP                | 只開 Pi                | 看閘道 MAC 會不會被換掉                                         |


先不要收 beacon flood，也不要用 `hping --flood` 假裝正常流量。SYN 這輪不收。

Pi 上的 `nids_collector.py` **每一場都要開**。  
`serial_collector.py` **只在第 2、3、4 場開**，而且是在 Windows 上跑，接的是燒錄那條 USB 線，不是在 Pi 上跑。

每一場攻擊的形狀都一樣：`正常 3 分鐘 → 打攻擊 → 再正常 3 分鐘`。  
第 1 場沒有攻擊，整段都是正常，所以拉長到 15–20 分鐘。

CSV 不要 `git add`。

---



## 事先一次

1. `main/net_config.h` 的 SSID／密碼改成租屋處的 AP，重新燒錄。`HIPS_ENABLE` 維持 0。
2. 路由器把 **client isolation / AP isolation / 訪客隔離關掉**。ESP32、Pi、Kali 連同一個 AP。
3. Pi 只留一個 collector。Windows 不要再跑 `session_windows.ps1`。
4. Kali：`export NIDS_SSID=<跟韌體一樣>`。攻擊前先 `./scripts/nids-sync.sh`。`sudo` 會清掉環境變數，下面的攻擊指令都用 `sudo -E`。
5. 畫面上出現 `ARMED` 之後，才開始算那 3 分鐘正常。開機後約 45 秒的校準不要算進去。

COM 埠用你燒錄時的那個，例如 `COM5`。不確定就看裝置管理員裡的連接埠。

---



## 時間從哪一刻開始算

`ARMED` 出現之後，先不要急著打。

接著開 collector。開 USB 有時會讓板子重開，畫面會從 READY 回到開機。若重開了，再等一次 `ARMED`，然後才開始算 3 分鐘。重開前錄到的那一段作廢。

3 分鐘內什麼都不要打。攻擊腳本自己會結束。結束後再等 3 分鐘，等板子連回 Wi-Fi、Pi 上又持續有新的一列，才把 collector 關掉。

---



## Deauth / Disassoc：兩支都要開

這兩種會把 ESP32 踢下同一個 Wi-Fi，Pi 上的 UDP 紀錄會中間空一段。USB 那支就是用來補這段空檔。所以 USB 要在踢下線之前就已經開著，而且整場不要關。

三個視窗，照這個順序：

### 1. Pi，先開，整場不要關

```bash
python3 host/collector/nids_collector.py
```

看到它開始收列就留著。

### 2. Windows，接著開，也是整場不要關

先不要開 `idf.py monitor`。若 Monitor 還開著，下面這支會自己關掉同一個 COM 埠上的 Monitor。燒錄還沒結束時它會等，不會把燒錄砍掉。

在專案目錄：

```powershell
& "$env:USERPROFILE\.espressif\python_env\idf5.5_py3.11_env\Scripts\python.exe" `
  scripts/serial_collector.py --port COM3 --standby --out data/raw/nids_serial_deauth.csv
```

把 `COM5` 換成你的埠。每一場的 `--out` 要換檔名，否則會覆蓋上一場。建議：

- 第一場 deauth：`data/raw/nids_serial_deauth.csv`
- 第一場 disassoc：`data/raw/nids_serial_disassoc1.csv`
- 第二場 disassoc：`data/raw/nids_serial_disassoc2.csv`

視窗出現這三行才算開好：

- `Opened COMx`
- `Listening for START/STOP labels on UDP :10000`
- `Standby: leave this running`

同一條 USB 會另外寫一個 `你的檔名.csv.log`，裡面是開機和斷線訊息。CSV 本身只留每個 100 ms 視窗那一列。

若這一步讓板子重開，回到上面說的：等 `ARMED`，再開始算 3 分鐘。

### 3. Kali 不用再設 Windows 位址

攻擊腳本會把 START/STOP 送到兩個地方：Pi 仍走原本的 9999，Windows 的 USB collector 走 VMnet1 那台的 `10000`。位址用 host-only 網卡上的 `.1`（一般是 `192.168.124.1`）。不用每次 `export`。

Kali 上要先有這份 `host/attacks/netconfig.sh`。VMnet 不是這個網段時才覆寫：`export NIDS_WIN_GATEWAY=<Windows 的 VMnet1 IP>`。

### 4. 然後才打

```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
```

停手 3 分鐘。兩支 collector 都已經在跑，這段還是正常，不要打。

Deauth：

```bash
sudo -E ./host/attacks/attack_deauth.sh
```

Disassoc（這輪用 90 秒，而且要做兩場）：

```bash
sudo -E env NIDS_DISASSOC_SEC=90 ./host/attacks/attack_disassoc.sh
```

腳本結束後：

```bash
sudo -E ./host/attacks/prepare_wifi.sh managed
```

再等 3 分鐘。等板子連回去，Pi 又持續印新的一列。

### 5. 怎樣算這場有收到

- Pi 印出 `ATTACK START`，結束時印出 `ATTACK STOP`。中間 UDP 變少或停掉是預期的。
- Windows 那個視窗也要印 `ATTACK START` 和 `ATTACK STOP`。攻擊進行中，USB 的列還要繼續出現。
- Kali 要印出 `label mirror -> ...:10000`。若 Windows 沒有 START/STOP，多半是 serial collector 還沒開，或 VMnet1 的 `.1` 不是這台 Windows。這一場作廢，重來。



### 6. 關掉，留下兩個檔

先 Ctrl+C 停 Pi，得到一個 `nids_dataset_*.csv`。  
再 Ctrl+C 停 Windows，得到你 `--out` 的那個 CSV。

這兩個檔都留著，不要合成一個。下一場重新開 Pi collector；deauth / disassoc 也要重新開 serial collector，並且換 `--out`。

---



## 其他場：不要開 serial collector

正常、probe、evil twin、auth、ARP 都只開 Pi。USB 那支不要開，否則多一個用不到的檔，COM 埠也會被佔住。

1. 等 `ARMED`。
2. Pi：`python3 host/collector/nids_collector.py`
3. 正常 3 分鐘。第 1 場改成什麼都不打，錄 15–20 分鐘，然後直接 Ctrl+C。
4. 攻擊場才做下面這段。

Probe、auth、twin：

```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_probe_flood.sh
# 或 attack_evil_twin.sh、attack_auth_flood.sh
sudo -E ./host/attacks/prepare_wifi.sh managed
```

ARP 不要切到 monitor。Kali 用一般連線掛在同一顆 AP 上：

```bash
sudo -E ./host/attacks/prepare_wifi.sh managed
sudo -E ./host/attacks/arpspoof.sh
```

1. 攻擊結束再正常 3 分鐘，Pi 上要看到 `ATTACK START` 和 `ATTACK STOP`。
2. Ctrl+C。下一場重新開 Pi collector。

---



## 隔離是關掉，不是打開

「網路隔離」是路由器上的 client isolation。關掉之後，同一顆 AP 上的裝置才看得到彼此。ARP 要靠 Kali 的一般連線打到 ESP32；隔離開著，閘道那一欄會全程不變。

Auth、probe、deauth、disassoc、twin 是監聽注入，不靠這條路送攻擊封包。標籤是 Kali 經 VMnet1 送到 Pi 和 Windows，跟 Wi-Fi 隔離無關。

Auth 在手機熱點上看不見，是熱點自己幾乎不把認證幀放出來，不是因為少開了一層隔離。租屋處這顆 AP 關隔離後收一場即可。