# NIDS 專題筆記（組員共用）

> 專案：ESP32 輕量多模態入侵偵測  
> 目的：快速對齊架構、目錄、日常實驗流程，方便 trace code  
> 格式：純 Markdown（查閱用）。若要做成簡報可再拆 Marp。

---

## 1. 一句話在做什麼

在 **ESP32** 上結合：

- **NIDS**：802.11 特徵（subtype、RSSI/SNR、封包密度…）
- **HIDS**：主機狀態（heap、reconnect、UDP fail、backlog…）

以 **100ms 時間窗** 聚合 → 輕量決策樹（`model.h`）在板端推論 → 可選 **HIPS**（黑名單 / 暫斷隔離）。

**不需要樹莓派當「唯一 collector」。** Collector 可跑在 Windows/Kali PC。  
但若實驗是 **deauth 會把 Wi-Fi 打斷**，單靠「同一條 Wi-Fi 上的 UDP syslog」**不能**保證攻擊當下即時送達——這點見下方 §2.1。

---

## 2. 實驗網路拓撲

```
Kali VM (USB Wi-Fi)  --空中攻擊-->  ESP32
Kali VM              --label START/STOP-->  Collector (Windows)   [VMNet1 host-only]
ESP32                --syslog UDP------->  Collector             [手機熱點，IP 自動探索]
Collector            --UDP beacon------->  ESP32                 [:5005]
```

| 通道 | 路徑 | 說明 |
|------|------|------|
| Syslog | ESP32 → Host Wi-Fi → Collector `:1514` | 特徵資料；**不再寫死 IP**（auto-discovery） |
| Discovery | Collector 廣播 → ESP32 `:5005` | ESP32 學到 collector IP |
| Label | Kali → `192.168.220.1:9999`（VMNet1） | 標註攻擊區間；不受熱點斷線影響 |

### 2.1 Deauth 斷線 vs 當初的樹莓派 / eth0（必讀）

當初把收集放到 **Pi + eth0（或筆電 relay → Pi）**，核心不是「一定要樹莓派這個牌子」，而是要一條 **不受 deauth 影響的 out-of-band 通道**：攻擊打的是 Wi-Fi 關聯，syslog 若也走同一條 Wi-Fi，斷線期間 UDP 會送不出去。

| 做法 | 攻擊當下能否穩收 | 現況 |
|------|------------------|------|
| Wi-Fi UDP syslog（現在預設 `SYSlOG_MODE=1`） | 斷線時不行 | 有 **RAM backlog**，重連後再 flush；久攻可能 `dropped` |
| **USB 序列埠**（`SYSlOG_MODE=2` + `serial_collector.py`） | **可以**（不依賴 Wi-Fi） | 已實作，**deauth 實驗首選** |
| 有線 / Pi / `udp_relay.py` 轉送 | 可以（若 ESP32 側有獨立連線） | 舊架構仍可用，非必須 |

**Auto-discovery 只解決「換場地改 IP」，沒有取代 out-of-band。**  
Label 走 VMNet1 只保證 **Kali→Windows 的 START/STOP** 不斷，不保證 ESP32 的 syslog 在 deauth 時還走得通。

**建議實驗策略：**

- **Deauth / 會斷 Wi-Fi：** 優先 **Pi 有線收集**（維持舊 out-of-band）；備援是 `SYSlOG_MODE=2` USB 序列埠  
- **SYN / ARP（關聯多半還在）：** Windows 或 Pi 跑 collector + Wi-Fi UDP + auto-discovery  
- Label 一律：Kali → 跑 collector 那台的 host-only / 固定 IP（常見 `192.168.220.1:9999`）

熱點若開 **AP isolation** 擋 client 互傳：即使沒 deauth，UDP 也可能失敗 → 查熱點設定，或改序列埠 / Pi 有線。

### 2.2 回家實測依序 SOP（Pi + ESP32 + Kali）

> 不用每天開資料夾就跑；**只有要收資料 / 攻擊時**照這份。  
> 一次實驗建議只驗證一條線（先 syslog 通，再打攻擊）。

#### 出發前帶什麼

| 必帶 | 可選 |
|------|------|
| ESP32 + USB 線 | 樹莓派 + 網線（**deauth 正式收資料強烈建議**） |
| Windows 筆電（ESP-IDF + collector） | 手機熱點（SSID 對齊 `net_config.h`，預設 `302`） |
| Kali VM（VMware）+ **USB Wi-Fi** passthrough | — |

#### Kali：SSH 還是直接開？

| 方式 | 何時用 |
|------|--------|
| **VMware 視窗直接開終端** | 第一次接網卡、開 monitor、debug 介面名稱（`wlan0`/`wlan0mon`） |
| **Windows → SSH 進 Kali** | 網卡已 OK、之後只跑攻擊指令（較省事） |

兩者都可以；**第一次回家建議先直接開**，確認 `iwconfig` / monitor 正常後，之後再用 SSH。

---

#### 開機順序（照做）

```
① 熱點 / AP 開好（SSID=302 或與韌體一致）
② 樹莓派開機 + 接 eth0（若今天要做 deauth / 要 OOB 收集）
③ Windows：開 VMware → Kali（USB Wi-Fi 勾給 VM）
④ Windows：ESP32 USB 接上 → 燒錄 / monitor
⑤ 跑 collector（在「負責收 syslog」的那台：Pi 或 Windows）
⑥ Kali：git pull → 設目標 → 攻擊
```

---

#### Step 0 — 網路角色先想清楚（今天用哪種）

**模式 D（Deauth / 正式 OOB，推）**

```
ESP32 --(有線或你們既有的 Pi 路徑)--> Pi 跑 nids_collector.py
Kali  --VMNet1 label--> Pi 或 Windows（看 label 聽在哪）
Kali  --USB Wi-Fi 空中--> ESP32（deauth）
```

**模式 W（SYN/ARP 或快速聯調）**

```
ESP32 --Wi-Fi UDP--> Windows 跑 nids_collector.py（auto-discovery）
Kali  --VMNet1 label--> Windows 192.168.220.1:9999
Kali  --USB Wi-Fi--> ESP32
```

**模式 S（沒帶 Pi 又要測 deauth）**

```
ESP32 --USB serial--> Windows serial_collector.py（SYSlOG_MODE=2）
Kali  --label--> Windows
```

---

#### Step 1 — 樹莓派（模式 D 才需要）

1. 開機，確認 eth0 / 與 Windows 或 ESP32 的連線方式與以前相同  
2. `git pull` 專案（或同步你們慣用的目錄）  
3. 啟動 collector：
   ```bash
   cd /path/to/nids_esp32_project
   python3 host/collector/nids_collector.py
   # 或舊習慣的埠；需能收 syslog + :9999 label
   ```
4. 記下 Pi 的 IP；若 label 打到 Pi，Kali 要：
   ```bash
   export NIDS_LABEL_HOST=<Pi的IP或Windows轉發目標>
   ```
5. （可選）Windows 若當中繼：`python scripts/udp_relay.py ...` 轉到 Pi  

驗收：Pi 終端開始出現 syslog 或至少 beacon 有在跑。

---

#### Step 2 — Windows + ESP32

1. 開 **ESP-IDF** PowerShell：
   ```powershell
   cd ...\nids_esp32_project
   idf.py build flash monitor
   ```
2. 確認 `main/net_config.h` 的 SSID/密碼 = 熱點  
3. Monitor 上看：連上 Wi-Fi、（UDP 模式）有 `Discovered collector` 或 backlog 在降  
4. **今天模式：**
   - **D（Pi）：** 韌體 syslog 指到能到 Pi 的路徑（discovery 學到 Pi，或你們既有靜態/有線設定）  
   - **W：** Windows：`.\scripts\session_windows.ps1`  
   - **P：** Pi：`./scripts/bringup.sh`  
   - **S：** `SYSlOG_MODE=2` 重燒後：`python scripts\serial_collector.py --port COMx`

驗收：collector（Pi 或 Windows）有持續進資料 / CSV 在長。

---

#### Step 3 — Kali（直接開或 SSH）

**A. 直接開（建議第一次）**

1. VMware 視窗進 Kali  
2. USB Wi-Fi 已 passthrough；確認介面：
   ```bash
   ip link
   # managed: wlan0；deauth 前開 monitor → wlan0mon
   ```
3. `cd` 到專案，`git pull`，`chmod +x scripts/*.sh host/attacks/*.sh`（首次）

**B. SSH（之後常用）**

1. Windows：`ssh kali@<Kali的VMNet1 IP>`  
2. 同上 `cd` + `git pull`  
3. 注意：sudo 攻擊、monitor 模式在 SSH 下通常仍可用（網卡已在 VM 內）

**取得攻擊目標（二選一）**

```bash
# 在 Windows/Pi 跑 print_live_targets，把 export 貼進 Kali：
export NIDS_ESP32_IP=...
export NIDS_ESP32_MAC=...
export NIDS_LABEL_HOST=192.168.220.1   # 或改成 Pi IP
export NIDS_MON_IFACE=wlan0mon
export NIDS_WIFI_IFACE=wlan0
```

（若 `data/live_state.json` 有掛到 Kali，也可：`./scripts/print_live_targets.sh`）

---

#### Step 4 — 依攻擊類型開打（先 START 環境再攻擊）

| 攻擊 | Kali | Collector 建議 | 攻擊前確認 |
|------|------|----------------|------------|
| **Deauth** | `sudo ./host/attacks/attack_deauth.sh` | **Pi 或 serial** | monitor 起來；label host 正確 |
| **SYN** | `sudo ./host/attacks/syn_flood.sh` | Windows/Pi UDP 皆可 | ESP32 與 Kali 同熱點；HTTP :80 |
| **ARP** | `sudo ./host/attacks/arpspoof.sh` | 同上 | managed 介面在熱點上 |

驗收：

- Collector 出現 `ATTACK START/STOP`  
- CSV 裡對應區間 `label=1`  
- Deauth 時：Pi/serial **仍持續有列**（若只有 Wi-Fi UDP 且螢幕停住 → 符合預期，換模式 D/S）

---

#### Step 5 — 收工

1. Kali：停攻擊、可關 monitor  
2. Collector：Ctrl+C，確認 `data/raw/nids_dataset_*.csv`（或 Pi 上同等路徑）已存  
3. 大檔 → Google Drive；小改 code → `git commit`（**不要 commit CSV**）  
4. ESP32 斷電 / 拔線；Pi 關機  

---

#### 15 分鐘最小驗收（第一次回家）

1. ESP32 flash + 連熱點 OK  
2. Collector 有資料進來（先别管攻擊）  
3. Kali `ping` 得到 label 主機（`192.168.220.1` 或 Pi）  
4. 跑一次短 deauth **或** 一次短 SYN，看得到 START/STOP  

全過再談平衡資料集與重訓 `model.h`。

---

## 3. UDP 傳輸怎麼改的（trace 重點）

**以前：** `main.c` 寫死 `YOUR_CPU_IP_ADDR`，換場地重燒。

**現在：**

1. Host 跑 collector → 對 `255.255.255.255:5005` 廣播 `NIDS_DISCOVERY`
2. ESP32 `collector_discovery_task` 聽 beacon，用來源 IP 當 syslog 目的地
3. 未發現前 syslog 進 backlog，發現後 flush
4. Collector 把 ESP32 的 IP/MAC 寫入 `data/live_state.json` 給攻擊腳本用

設定集中：`main/net_config.h`（SSID、埠、HIPS 開關）。

---

## 4. 倉庫目錄（整理後）

```
main/                      ESP-IDF 韌體（根目錄給 idf.py，勿亂搬）
  net_config.h             Wi-Fi / discovery / HIPS
  main.c                   sniffer、discovery、100ms 窗、推論、HIPS
  model.h                  m2cgen 產生，勿手改

host/
  paths.py                 共用路徑（data/、live_state、model.h）
  collector/nids_collector.py
  attacks/
    netconfig.sh / prepare_wifi.sh
    attack_deauth.sh / syn_flood.sh / arpspoof.sh
  train/
    nids_features.py       特徵欄位契約（與韌體 / model.h 對齊）
    aggregate_windows.py
    analyze_and_train.py

scripts/
  session_windows.ps1      Windows 開 collector
  bringup.sh               Pi/Linux 開 collector
  bringup.py               被 session_windows 呼叫（不必手動開）
  print_live_targets.ps1 / .sh
  serial_collector.py      AP isolation / deauth 備援

data/                      本機資料（不進 Git）→ 大檔用 Google Drive
docs/                      筆記、bib、圖、計畫 PDF
archive/                   舊雙份腳本、帳密（勿 push login）
note/                      note.md + lab_runbook.md
```

---

## 5. Shell vs Python

| 工作 | 用什麼 | 原因 |
|------|--------|------|
| 攻擊、prepare_wifi、Pi bringup | **bash `*.sh`** | Kali/Pi 原生 |
| Windows 開 collector | `session_windows.ps1` | Windows 入口 |
| Collector / 訓練 | Python | UDP 解析、sklearn、m2cgen |

---

## 6. 機器分工（Windows 編韌體 + Kali 攻擊）

| 機器 | 職責 | 需要的東西 |
|------|------|------------|
| **Windows** | `idf.py` 編譯燒錄、跑 collector、訓練 | 整份 repo |
| **Kali VM** | 攻擊 + label | `git pull` 後主要用 `host/attacks/*.sh` |

**不要整包手動複製 code** → 用 GitHub：`push` / `pull`，避免兩端版本漂移。

### `live_state.json` 怎麼給 Kali

檔在 Windows 的 `data/live_state.json`，Kali 預設看不到。任選：

1. Windows 跑 `.\scripts\print_live_targets.ps1`，把 `export` 貼到 Kali（**最簡單**）
2. VMware 共用資料夾掛 `data/`
3. 手動 scp（較煩）

Label 固定打 Windows 的 VMNet1：`NIDS_LABEL_HOST=192.168.220.1`。

---

## 7. 日常流程（不是每次開資料夾都要跑）

**改 code / 寫報告 → 什麼都不用跑。**  
**只有要收資料或攻擊時才開 session。**

### Windows

```powershell
# 韌體有改才需要：
# idf.py build flash monitor

.\scripts\session_windows.ps1
# 另開一個終端：
.\scripts\print_live_targets.ps1
# 把 export 貼給 Kali
```

### Kali

```bash
git pull
chmod +x scripts/*.sh host/attacks/*.sh   # clone 後做一次即可

# 貼上 Windows 印出的 export 後：
sudo ./host/attacks/attack_deauth.sh
sudo ./host/attacks/syn_flood.sh
sudo ./host/attacks/arpspoof.sh
```

### 收完資料後（Windows）

```powershell
python host/train/aggregate_windows.py
python host/train/analyze_and_train.py
# → 更新 main/model.h、docs/figures/
# 再 flash 一次才會讓板上模型變新
```

大 CSV → Google Drive（見 `data/README.md`），**不要 commit 進 Git**。

---

## 8. 重要環境變數

| 變數 | 用途 |
|------|------|
| `NIDS_ESP32_IP` / `NIDS_ESP32_MAC` | 攻擊目標（來自 live_state 或手貼） |
| `NIDS_BSSID` | Deauth 用 AP BSSID |
| `NIDS_WIFI_IFACE` / `NIDS_MON_IFACE` | 預設 `wlan0` / `wlan0mon` |
| `NIDS_LABEL_HOST` / `NIDS_LABEL_PORT` | 預設 `192.168.220.1` / `9999` |
| `NIDS_SSID` | 預設 `302`（需與 `net_config.h` 一致） |

---

## 9. Trace code 路線圖

**板上推論：**

`main.c` sniffer → 100ms 聚合填 `nids_window_features_t` → `nids_predict()`（`model.h`）→ OLED / `nids_mitigate()`（HIPS）

**資料進 PC：**

`main.c` syslog UDP → `host/collector/nids_collector.py` → `data/raw/*.csv` + `data/live_state.json`

**標註：**

Kali `*.sh` → `send_label` → collector control port → CSV 的 `label` / `attack_type`

**訓練上板：**

`aggregate_windows.py` → `data/windows/` → `analyze_and_train.py` → `main/model.h` → flash

特徵欄位單一真相：`host/train/nids_features.py`（改欄位必須同步韌體填值與重訓）。

---

## 10. Git / 協作注意

- **勿 commit：** `data/raw/**`、`data/windows/**`、`live_state.json`、`build/`、`sdkconfig`、帳密（`archive/raspberry login.txt`）
- `model.h` 由訓練腳本產生；PR 時說明用哪份資料集訓練
- 組員有 ESP32、無 Pi：自己 flash + 可跑 train；攻擊與平衡資料集可集中一人收完再丟 Drive

---

## 11. 已知資料問題（寫 paper 前必看）

既有測試集偏 SYN、NORMAL 偏少；ARP 等攻擊樣本不足會讓 per-attack recall 失真。  
評估看 **F1 / Recall / AUC**，不要只報 accuracy。正式數字前請重收平衡資料。

---

## 12. 相關文件

| 檔案 | 內容 |
|------|------|
| `note/lab_runbook.md` | **實測當天：誰開什麼、Pi/Windows 流程** |
| `README.md` | 快速上手 |
| `data/README.md` | Drive 分享約定 |
| `docs/` | 計畫書 PDF、架構圖、figures |
