# 實測 Runbook：誰開什麼、何時開

> 和 `note.md`（架構 / 設計說明）分開。  
> 這份給**組員共用**：實驗日每台機器依序做什麼。  
> 個人出發清單／本機帳密 → `note/private/`（不上 Git）。

---

## 0. 組員先看：要不要改 IP？

| 通常不用改 | 每人要對齊自己環境 |
|------------|-------------------|
| Collector IP（靠 UDP discovery `:5005`） | `main/net_config.h` 的 **SSID／密碼** → 重燒 |
| Kali label（讀 `live_state.json` 的 `label_host`） | VMware host-only **子網**（各人可能不同） |
| `COLLECTOR_FALLBACK_IP` 維持 `""` | discovery 失敗才填**自己的** collector Wi‑Fi IP |

細節表見 `note/note.md` §2.0。

---

## 1. 先選今天的模式（只選一個）

| 模式 | Collector 在哪 | 適合 |
|------|----------------|------|
| **P — Pi** | 樹莓派 | 正式收一場：NORMAL + Deauth + SYN + ARP（中間穿 NORMAL） |
| **W — Windows** | Windows | 快速聯調、沒帶 Pi（也可打多種；deauth 較不穩） |
| **S — Serial** | Windows USB 序列埠 | 沒 Pi 又要穩收含 deauth 的場次 |

下面先寫 **P** 與 **W**（最常用）；**S** 在文末。

---

## 2. 各腳本是什麼？

| 名稱 | 做什麼 | 誰跑 | 何時 |
|------|--------|------|------|
| `session_windows.ps1` | Windows 開 collector（內部叫 `bringup.py`） | Windows | 模式 W |
| `host/collector/nids_collector.py` | 真正收 syslog 的程式 | **Pi 或 Windows** | 實驗期間一直開 |
| `bringup.sh` | （可選）Pi/Linux 包裝：印說明 + 啟動 collector | Pi | 等效於直接跑 collector |
| `print_live_targets.ps1` / `.sh` | 印 Kali 用的 `export` | Win 或 Pi | 攻擊前（可選） |
| `prepare_wifi.sh` | monitor ↔ managed + VMnet1 eth0 | Kali | Deauth 前 / SYN·ARP 前 |
| `attack_deauth.sh` 等 | 攻擊 + label | Kali | 同一時間一支 |
| `netconfig.sh` | 給上面 `.sh` source | Kali | 自動被 source |
| `aggregate_windows.py` / `analyze_and_train.py` | 訓練管線 | 有 Python/ML 的機器 | **收完資料後** |

**記法：**  
- Windows 當 collector → `session_windows.ps1`  
- Pi 當 collector → `python3 host/collector/nids_collector.py`  
- Kali → `prepare_wifi` + 攻擊 `.sh`  

**Kali 不跑** train。只改 code / 寫報告 → 不必開 collector／攻擊。

---

## 3. 模式 P — Pi 收資料

> 同一場 collector 開著，依序跑完各攻擊，中間穿 **NORMAL**，資料集才平衡。

### 角色

| 機器 | 要開的 | 不要開 |
|------|--------|--------|
| **Pi** | `python3 host/collector/nids_collector.py`（整場開著） | 攻擊腳本 |
| **Windows** | `idf.py build flash monitor` | `session_windows`（別跟 Pi 搶 collector） |
| **Kali** | `prepare_wifi.sh` + 各 `attack_*.sh` | collector / train |

### 依序

```text
① 開熱點（SSID／密碼對齊 net_config.h）
② Pi：python3 host/collector/nids_collector.py
③ Windows：ESP32 flash monitor；確認 Pi 有持續 syslog
④ Kali：能讀同一份 live_state.json 即可（否則再 export NIDS_LABEL_HOST）
```

**建議同一場順序（每種之間留 NORMAL）：**

```text
⑤ 先收 2–5 分鐘 NORMAL
⑥ Deauth：
     sudo ./host/attacks/prepare_wifi.sh monitor
     sudo ./host/attacks/attack_deauth.sh
     → 等 ESP32 重連、collector 又穩定
⑦ 再收 1–2 分鐘 NORMAL
⑧ SYN：
     sudo ./host/attacks/prepare_wifi.sh managed
     # 連回熱點後：
     sudo ./host/attacks/syn_flood.sh
⑨ 再收 1–2 分鐘 NORMAL
⑩ ARP：sudo ./host/attacks/arpspoof.sh
⑪ 最後再收一段 NORMAL
⑫ Collector Ctrl+C → 保存 CSV（大檔用約定管道分享，勿 commit）
⑬ （可改天）aggregate_windows → analyze_and_train → flash
```

每打完一種，collector 應出現對應 `ATTACK START/STOP`。

### 各攻擊前 Kali 介面

| 攻擊 | 先跑 | 網卡 |
|------|------|------|
| Deauth | `prepare_wifi.sh monitor`（缺 mon 時 deauth 會自動叫） | `wlan0mon` |
| SYN / ARP | `prepare_wifi.sh managed` + 連熱點 | `wlan0` managed |

### Label

- 平常不必手打 `NIDS_LABEL_HOST`：collector 寫入 `data/live_state.json` 的 `label_host`。
- Kali 要能讀到**同一份** `live_state.json`（共享資料夾／同 repo 路徑）。
- 猜錯再覆寫：`export NIDS_LABEL_HOST=...`，或在跑 collector 的機器設 `NIDS_LABEL_ADVERTISE=...`。

### Kali：SSH 還是視窗？

- 第一次接網卡／切 monitor：VMware **直接開**
- 之後：SSH 也可

---

## 4. 模式 W — Windows 當 Collector

| 機器 | 要開的 |
|------|--------|
| **Windows** | `.\scripts\session_windows.ps1` + ESP32 flash/monitor |
| **Kali** | `prepare_wifi` + 攻擊 `.sh`；label 多半是 VMnet1 上的 Windows（見 `live_state`） |
| **Pi** | 不需要 |

```text
① 熱點
② Windows：ESP32 flash monitor
③ Windows：.\scripts\session_windows.ps1
④ （可選）.\scripts\print_live_targets.ps1
⑤ Kali：攻擊腳本
⑥ 收工後可跑 aggregate → analyze_and_train
```

不要同時再開 `bringup.py`（`session_windows` 已會叫它）。

---

## 5. 模式 S — 沒 Pi 的 deauth（USB 序列埠）

```text
① 韌體 SYSlOG_MODE=2，重新 flash
② Windows：python scripts/serial_collector.py --port COMx
③ Kali：label 打到跑 serial collector 的那台（常見 VMnet1 host）
④ 攻擊 deauth
```

---

## 6. Kali 最小指令（模式 P）

```bash
cd /path/to/repo

# --- Deauth ---
sudo ./host/attacks/prepare_wifi.sh monitor
sudo ./host/attacks/attack_deauth.sh

# --- SYN / ARP ---
sudo ./host/attacks/prepare_wifi.sh managed
# 連上 SSID 後：
sudo ./host/attacks/syn_flood.sh
sudo ./host/attacks/arpspoof.sh
```

同一時間 **只跑一支** 攻擊腳本。

`prepare_wifi.sh`：開 `wlan0mon`、設 channel、把 host-only 介面設成 VMnet1 位址（預設常見 `192.168.220.50/24`；以各人 VMware 為準）。介面名不同則設 `NIDS_HOSTONLY_IFACE=...`。

---

## 7. VMware 網卡（常踩雷）

| 網卡 | 建議 | 用途 |
|------|------|------|
| NIC1 | Host-only（VMnet1） | SSH、（模式 W）label |
| NIC2 | NAT（可選） | Kali 上網 / git |
| USB Wi-Fi | 傳給 VM | 空中攻擊 |

Host-only 子網以本機 VMware 為準（可能是 `192.168.220.x` 或 `192.168.124.x`）。以 `live_state.json` 的 `label_host` 為準，不要死背文件裡的範例 IP。

---

## 8. 收完資料才跑（離線）

```text
aggregate_windows.py  →  100ms 視窗 CSV
analyze_and_train.py  →  model.h + docs/figures/
idf.py flash          →  板上用新模型
```

與 Pi/Kali 是否開機無關；通常在 Windows 跑。

---

## 9. 30 秒速查

| 我想… | 開這個 |
|------|--------|
| Pi 正式收一場 | Pi: `nids_collector.py`；Win: flash；Kali: NORMAL→攻擊，label→live_state |
| Windows 快速 SYN | Win: `session_windows.ps1` + flash；Kali: syn_flood |
| 給 Kali 目標 | `print_live_targets` 或讀 `live_state.json` |
| 訓練出新 model | aggregate_windows → analyze_and_train |
| 只改程式 | 不必開 session / collector / 攻擊 |

---

## 10. 文件分工

| 檔案 | 內容 |
|------|------|
| `note/note.md` | 架構、為何要 OOB、UDP discovery、目錄 |
| `note/lab_runbook.md`（本檔） | **實驗日步驟（組員共用）** |
| `note/private/` | 個人備忘（gitignore） |

### 常見聯調注意（收資料前）

- 同一台機器不要開兩個 collector（`:1514` Address already in use）
- Monitor 上 `Syslog UDP → …`／collector 有刷行，再開始打攻擊
- 板上舊模型可能一直 `[INFERENCE] attack`：收資料時保持 `HIPS_ENABLE 0`；重訓後再開
- Syslog 若約 `255B` 且 parse 失敗：韌體 buffer 過舊，需 flash 含較大 syslog buffer 的版本
