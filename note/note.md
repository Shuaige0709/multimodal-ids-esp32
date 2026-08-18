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
Kali VM              --label START/STOP-->  Collector            [OOB：見下方]
ESP32                --syslog UDP------->  Collector             [同一 Wi‑Fi：AP 或熱點；IP 自動探索]
Collector            --UDP beacon------->  ESP32                 [:5005]
```

| 通道 | 路徑 | 說明 |
|------|------|------|
| Syslog | ESP32 → Host Wi-Fi → Collector `:1514` | 特徵資料；**auto-discovery**（不必寫死 collector IP） |
| Discovery | Collector 廣播 → ESP32 `:5005` | ESP32 學到 collector IP |
| Label | Kali → 跑 collector 那台的 `:9999` | 看 `live_state.json` 的 `label_host`（Mode W 常為 Windows VMnet1；Mode P 常為 Pi eth0） |

**Mode P 注意：** Pi eth0（label／SSH）若接在 Windows 有線／USB eth（例如 `10.0.0.0/24`），而 Kali 只有 VMnet1（例如 `192.168.124.0/24`），兩邊**不是同一 L2**。Windows 能 ping Pi ≠ Kali 能 ping Pi。需要 Windows IP forwarding + Kali 路由 `via 192.168.124.1` + Pi 回程路由。細節見 [`lab_runbook.md`](lab_runbook.md)「Mode P 常見網路落差」。

### 2.0 組員要改什麼？（IP／SSID）

**多數情況不用手填 IP。** Collector 開著會廣播 beacon；ESP32 學到目的地；Kali 讀 `data/live_state.json`。

| 項目 | 誰改 | 怎麼做 |
|------|------|--------|
| **AP／熱點 SSID／密碼** | 每人 flash 前 | 改 `main/net_config.h` 的 `WIFI_SSID` / `WIFI_PASS`，重燒 |
| **Kali 攻擊 SSID** | Kali | `export NIDS_SSID=...`（與 net_config 一致；腳本預設 `302`） |
| Collector IP | 通常不用 | 留 `COLLECTOR_FALLBACK_IP ""`；靠 discovery |
| Label（Kali→collector） | 通常不用 | 攻擊腳本讀 `live_state.label_host`；Mode P 先 **`./scripts/nids-sync.sh`** |
| VMware host-only 子網 | 各人本機 | 以 VMware 實際為準，**不要抄別人的範例 IP** |
| Kali host-only 位址 | Kali | `prepare_wifi` 預設 `192.168.124.50/24`；子網不同就設 `NIDS_HOSTONLY_IP=...` |

實驗步驟細節見 [`lab_runbook.md`](lab_runbook.md)。組員在**固定 AP**重試 ARP/AUTH → [`docs/HELP.md`](../docs/HELP.md)。

### 2.1 Deauth 斷線 vs 當初的樹莓派 / eth0（必讀）

當初把收集放到 **Pi + eth0（或筆電 relay → Pi）**，核心不是「一定要樹莓派這個牌子」，而是要一條 **不受 deauth 影響的 out-of-band 通道**：攻擊打的是 Wi-Fi 關聯，syslog 若也走同一條 Wi-Fi，斷線期間 UDP 會送不出去。

| 做法 | 攻擊當下能否穩收 | 現況 |
|------|------------------|------|
| Wi-Fi UDP syslog（現在預設 `SYSlOG_MODE=1`） | 斷線時不行 | 有 **RAM backlog**，重連後再 flush；久攻可能 `dropped` |
| **USB 序列埠**（`SYSlOG_MODE=2` + `serial_collector.py`） | **可以**（不依賴 Wi-Fi） | 已實作，**deauth 實驗首選** |
| 有線 / Pi / `udp_relay.py` 轉送 | 可以（若 ESP32 側有獨立連線） | 舊架構仍可用，非必須 |

**Auto-discovery 只解決「換場地改 IP」，沒有取代 out-of-band。**  
Label 走 host-only／有線 OOB 只保證 **Kali→collector 的 START/STOP** 不斷，不保證 ESP32 的 syslog 在 deauth 時還走得通。

**建議實驗策略：**

- **Deauth / 會斷 Wi-Fi：** 優先 **Pi 有線收集**（維持舊 out-of-band）；備援是 `SYSlOG_MODE=2` USB 序列埠  
- **SYN / ARP（關聯多半還在）：** Windows 或 Pi 跑 collector + Wi-Fi UDP + auto-discovery  
- Label 一律：Kali → `live_state.json` 的 `label_host`（Windows 模式常為 VMnet1 上的主機 IP）

**AP／熱點若開 client isolation** 擋 client 互傳：即使沒 deauth，UDP syslog 與 **ARP 煙測（`gw_flip`）** 也可能失敗 → 關隔離，或改序列埠 / Pi 有線。詳見 [`docs/HELP.md`](../docs/HELP.md)。

### 2.3 攻擊可見性（煙測摘要，非 train 結論）

| 攻擊 | 手機熱點（已試） | 備註 |
|------|------------------|------|
| DEAUTH | OK | 板上主線 |
| SYN_FLOOD | 部分 | 密度／HIDS |
| ARP_SPOOF | fail | `gw_flip` 全程 0 |
| AUTH_FLOOD | weak | `auth_packets` 幾乎平坦 |
| PROBE_FLOOD | pass | 2026-08-18；未進 `model.h` |

固定 AP 上 ARP/AUTH 需組員重測 → [`docs/HELP.md`](../docs/HELP.md)。

### 2.2 實驗日怎麼跑（指向 runbook）

**逐步指令、誰開哪支程式：** 見 [`lab_runbook.md`](lab_runbook.md)（模式 P / W / S）。

這裡只記拓撲選擇原則：

| 模式 | Collector | 適合 |
|------|-----------|------|
| **P** | 樹莓派（Wi‑Fi UDP；deauth 時靠 backlog／或有線 OOB） | 正式收一場：NORMAL + 多種攻擊 |
| **W** | Windows `session_windows.ps1` | 快速聯調、沒帶 Pi |
| **S** | Windows USB serial（`SYSlOG_MODE=2`） | 沒 Pi 又要穩收 deauth |

一次實驗建議只驗證一條線（先 syslog 通，再打攻擊）。

Kali：第一次接 USB 網卡／開 monitor 建議 VMware 視窗直接操作；介面穩定後可用 SSH。

個人出發清單、本機 IP／SSH 備忘 → 放 `note/private/`（已 gitignore，不上 Git）。

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

data/                      多數本機；Phase A 基線 CSV 進 Git（見 `data/README.md`）
docs/                      筆記、bib、圖、計畫 PDF
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

Label：優先用 `live_state.label_host`；不對再 `export NIDS_LABEL_HOST=<跑 collector 那台 Kali 打得到的 IP>`（Windows 模式常見為 VMnet1 主機位址）。

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
chmod +x host/attacks/*.sh scripts/*.sh   # clone / pull 後做一次（否則 ./xxx.sh → command not found）

# 需有 NIDS_ESP32_MAC（live_state 或手貼 print_live_targets 的 export）後：
# deauth：自動短 airodump + 攻擊前 ping label_host（W/S→Windows；P→Pi）
# syn/arp：同樣先檢查 label 通路；一律建議 sudo -E
sudo -E ./host/attacks/attack_deauth.sh
sudo -E ./host/attacks/syn_flood.sh
sudo -E ./host/attacks/arpspoof.sh
```

### 收完資料後（Windows）

```powershell
python host/train/aggregate_windows.py
python host/train/analyze_and_train.py
# → 更新 main/model.h、docs/figures/
# 再 flash 一次才會讓板上模型變新
```

試收 CSV 勿亂 commit；鎖定基線才進 Git（見 `data/README.md`）。

---

## 8. 重要環境變數

| 變數 | 用途 |
|------|------|
| `NIDS_ESP32_IP` / `NIDS_ESP32_MAC` | 攻擊目標（來自 live_state 或手貼） |
| `NIDS_BSSID` | Deauth 用 AP BSSID |
| `NIDS_WIFI_IFACE` / `NIDS_MON_IFACE` | 預設 `wlan0` / `wlan0mon` |
| `NIDS_LABEL_HOST` / `NIDS_LABEL_PORT` | 覆寫 label 目標；未設則讀 `live_state`（後備常為 `192.168.124.1:9999`） |
| `NIDS_HOSTONLY_IP` | Kali host-only CIDR（`prepare_wifi`；子網與範例不同時必改） |
| `NIDS_SSID` | **AP／熱點名稱**（需與 `net_config.h` 一致；Kali 必 export） |

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

- **勿 commit：** 試收 `data/raw|windows`（基線除外）、`live_state.json`、`build/`、`sdkconfig`、帳密
- `model.h` 由訓練腳本產生；PR 時說明用哪份資料集訓練
- 組員：`git pull` 後 `chmod +x host/attacks/*.sh scripts/*.sh`；AP 煙測任務 → [`docs/HELP.md`](../docs/HELP.md)

---

## 11. 已知資料問題（寫 paper 前必看）

既有測試集偏 SYN、NORMAL 偏少；ARP 等攻擊樣本不足會讓 per-attack recall 失真。  
評估看 **F1 / Recall / AUC**，不要只報 accuracy。正式數字前請重收平衡資料。

---

## 12. 相關文件

| 檔案 | 內容 |
|------|------|
| `note/lab_runbook.md` | **實驗日：誰開什麼、Pi/Windows/Kali 流程** |
| `note/improvement_directions.md` | **可改進方向**（特徵合流、資料、攻擊覆蓋、與組員對齊） |
| `note/compare_wids_vs_nids.md` | WIDS 定義、與 `esp32_packet_monitor` 對照 |
| `README.md` | 快速上手 |
| `data/README.md` | 哪些 CSV 進 Git／如何 reproduce 基線 |
| `docs/` | 計畫書 PDF、架構圖、figures |
| `note/private/` | **個人備忘（gitignore，勿 push）** |
