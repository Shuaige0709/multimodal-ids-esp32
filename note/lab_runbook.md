# 實測 Runbook：誰開什麼、何時開

> 和 `note.md`（架構 / 設計說明）分開。  
> 這份只回答：**回家要測時，每台機器依序做什麼。**

---

## 0. 先選今天的模式（只選一個）

| 模式 | Collector 在哪 | 適合 |
|------|----------------|------|
| **P — Pi 完整版** | 樹莓派 | **回家正式收一場**：NORMAL + Deauth + SYN + ARP（中間穿 NORMAL） |
| **W — Windows 版** | Windows | 快速聯調、沒帶 Pi（也可打多種，deauth 較不穩） |
| **S — Serial 版** | Windows USB 序列埠 | 沒 Pi 又要穩收含 deauth 的場次 |

下面先寫 **P** 與 **W**（最常用）；**S** 在文末。

---

## 1. 各腳本是什麼？（已去掉 .py/.sh 雙份攻擊腳本）

| 名稱 | 做什麼 | 誰跑 | 何時 |
|------|--------|------|------|
| `session_windows.ps1` | Windows 開 collector（內部叫 `bringup.py`） | Windows | 模式 W |
| `host/collector/nids_collector.py` | 真正收 syslog 的程式 | **Pi 或 Windows** | 實驗期間一直開 |
| `bringup.sh` | （可選）Pi/Linux 包裝：印說明 + 啟動 collector | Pi | 想偷懶時用；**等效於直接跑 collector** |
| `print_live_targets.ps1` / `.sh` | 印 Kali 用的 `export` | Win 或 Pi | 攻擊前 |
| `prepare_wifi.sh` | monitor ↔ managed + VMnet1 eth0 | Kali | Deauth 前 / SYN·ARP 前 |
| `attack_deauth.sh` 等 | 攻擊 + label | Kali | 同一時間一支；一場可依序多種 |
| `netconfig.sh` | 給上面 `.sh` source | Kali | 自動被 source |
| `aggregate_windows.py` / `analyze_and_train.py` | 訓練管線 | Windows | **收完資料後** |

**已移除（改放 `archive/duplicates/`）：** 攻擊用的 `.py`、`netconfig.py`、`session_kali.sh`。

**記法：**  
- Windows 當 collector → `session_windows.ps1`（別手動糾結 `bringup.py`）  
- Pi 當 collector → **`python3 host/collector/nids_collector.py` 即可**  
- Kali → 只有 `prepare_wifi` + 攻擊 `.sh`  

**Kali 不跑** train。改 code / 寫報告 → 上面都不用開。

---

## 2. 模式 P — Pi 完整版（回家正式收資料）

> Pi 都開了就 **不要只打 deauth**。同一場 collector 開著，依序跑完各攻擊，  
> 中間穿插一段 **NORMAL（不攻擊）**，資料集才平衡、也好寫 paper。

### 角色

| 機器 | 要開的 | 不要開 |
|------|--------|--------|
| **Pi** | `python3 host/collector/nids_collector.py`（整場開著） | 攻擊腳本 |
| **Windows** | `idf.py build flash monitor` | `session_windows`（別跟 Pi 搶 collector） |
| **Kali** | `prepare_wifi.sh` + 各 `attack_*.sh` | collector / train |

### 依序：開機 → 確認收得到 → 完整攻擊清單

```text
① 開熱點（SSID 對齊 net_config.h）
② Pi：python3 host/collector/nids_collector.py
③ Windows：ESP32 flash monitor；確認 Pi 有 syslog
④ Kali：設好 export（含 NIDS_LABEL_HOST=<Pi的IP>）
```

**建議同一場的攻擊順序（每種之間留 NORMAL）：**

```text
⑤ 先收 2–5 分鐘 NORMAL（什麼攻擊都不要打）
⑥ Deauth 前（或攻擊腳本自動做）：
     sudo ./host/attacks/prepare_wifi.sh monitor
     # = 舊 set_wifi.sh：wlan0mon + eth0→VMnet1
     sudo ./host/attacks/attack_deauth.sh
     → 等 ESP32 重連、collector 又穩定進資料
⑦ 再收 1–2 分鐘 NORMAL
⑧ SYN 前切回 managed（必做）：
     sudo ./host/attacks/prepare_wifi.sh managed
     # 再手動連回熱點 SSID，然後：
     sudo ./host/attacks/syn_flood.sh
⑨ 再收 1–2 分鐘 NORMAL
⑩ ARP spoof  sudo ./host/attacks/arpspoof.sh
⑪ 最後再收一段 NORMAL
⑫ Collector Ctrl+C 存檔 → CSV 上 Drive
⑬ （可改天）aggregate_windows → analyze_and_train → flash
```

每打完一種，在 collector 上應看到對應的 `ATTACK START/STOP` 與 `attack_type`。

### 各攻擊前 Kali 介面狀態

| 攻擊 | 先跑 | 網卡 |
|------|------|------|
| Deauth | `prepare_wifi.sh monitor`（缺 mon 時 deauth 會自動叫） | `wlan0mon` |
| SYN / ARP | `prepare_wifi.sh managed` + 連熱點 | `wlan0` managed |

不要假設「開著 monitor 就能打 SYN」。

### Label

- 平常**不用手打** `NIDS_LABEL_HOST`：collector 會寫入 `data/live_state.json` 的 `label_host`，攻擊腳本自動讀。
- Kali 要能讀到同一份 `live_state.json`（共享資料夾 / 複製 / 同 repo 路徑）。
- 猜錯時再覆寫：`export NIDS_LABEL_HOST=...`，或在跑 collector 的機器設 `NIDS_LABEL_ADVERTISE=...`。

### Kali：SSH 還是視窗？

- 第一次接網卡 / 切 monitor：VMware **直接開**
- 之後：SSH 也可；**沒在收資料就關 VM**


## 3. 模式 W — Windows 當 Collector

### 角色

| 機器 | 要開的 |
|------|--------|
| **Windows** | `.\scripts\session_windows.ps1` + ESP32 flash/monitor |
| **Kali** | `prepare_wifi` + 攻擊 `.sh`；`NIDS_LABEL_HOST=192.168.220.1` |
| **Pi** | 不需要 |

### 依序

```text
① 熱點
② Windows：ESP32 flash monitor
③ Windows：
     .\scripts\session_windows.ps1
④ （可另開）.\scripts\print_live_targets.ps1 → 貼到 Kali
⑤ Kali：export + prepare_wifi + 一支 attack_*.sh
⑥ 收工後可跑 aggregate → analyze_and_train
```

不要同時再開 `bringup.py`（`session_windows` 已經會叫它）。

---

## 4. 模式 S — 沒 Pi 的 deauth（USB 序列埠）

```text
① 韌體 SYSlOG_MODE=2，重新 flash
② Windows：
     python scripts/serial_collector.py --port COMx
③ Kali：label 仍打 Windows（192.168.220.1）
④ 攻擊 deauth
```

---

## 5. Kali 最小指令（模式 P 一場完整收資料）

```bash
cd /path/to/nids_esp32_project
# 貼 export（含 NIDS_LABEL_HOST=Pi或Windows）

# --- Deauth ---
sudo ./host/attacks/prepare_wifi.sh monitor   # 可省略：deauth 發現沒 mon 會自動跑
sudo ./host/attacks/attack_deauth.sh

# --- SYN / ARP（必先切回 managed + 連熱點）---
sudo ./host/attacks/prepare_wifi.sh managed
# nmcli / nmtui 連上 SSID 後：
sudo ./host/attacks/syn_flood.sh
sudo ./host/attacks/arpspoof.sh
```

同一時間 **只跑一支** 攻擊腳本；`.py` 與 `.sh` 擇一（建議 `.sh`）。

`prepare_wifi.sh` = 舊 `archive/set_wifi.sh`：開 `wlan0mon`、設 channel、把 eth0 設成 VMnet1 位址（預設 `192.168.220.50/24`）。若 host-only 介面名不是 `eth0`，設 `NIDS_HOSTONLY_IFACE=...`。

---

## 6. VMware 網卡（與「誰開程式」無關但常踩雷）

| 網卡 | 建議 | 用途 |
|------|------|------|
| NIC1 | Host-only **VMnet1** | SSH、（模式 W 時）label → `192.168.220.1` |
| NIC2 | NAT（可選） | Kali 上網 / git |
| USB Wi-Fi | 傳給 VM | 空中攻擊 |

回復 default 若只剩 NAT：SSH 可能還行，但 **label 的 192.168.220.1 常會掛** → 請加回 VMnet1。

---

## 7. 收完資料才跑（離線）

```text
aggregate_windows.py  →  100ms 視窗 CSV
analyze_and_train.py  →  model.h + docs/figures/
idf.py flash          →  板上用新模型（有改 model.h 才需要）
```

與 Pi/Kali 是否開機無關；CSV 在哪台，就在有 Python/ML 的那台跑（通常 Windows）。

---

## 8. 30 秒速查

| 我想… | 開這個 |
|------|--------|
| Pi 正式收一場完整資料 | Pi: `nids_collector.py`；Win: flash；Kali: NORMAL→Deauth→SYN→ARP，label→Pi |
| Windows 快速 SYN | Win: `session_windows.ps1` + flash；Kali: syn_flood，label→220.1 |
| 給 Kali IP | 看 Pi/Win 的 live_state，或 print_live_targets |
| 訓練出新 model | aggregate_windows → analyze_and_train |
| 只改程式 | 什麼 session / collector / 攻擊都不用開 |

---

## 9. 和 `note.md` 的分工

| 檔案 | 內容 |
|------|------|
| `note/note.md` | 架構、為何要 Pi、UDP discovery、目錄、設計注意 |
| `note/lab_runbook.md`（本檔） | **實測當天照著做的步驟** |
