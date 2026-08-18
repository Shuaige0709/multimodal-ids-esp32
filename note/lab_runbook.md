# 實測 Runbook：誰開什麼、何時開

> 和 `note.md`（架構 / 設計說明）分開。  
> 這份給**組員共用**：實驗日每台機器依序做什麼。  
> 個人出發清單／本機帳密 → `note/private/`（不上 Git）。

---

## 0. 組員先看：要不要改 IP？

| 通常不用改 | 每人要對齊自己環境 |
|------------|-------------------|
| Collector IP（靠 UDP discovery `:5005`） | **`main/net_config.h` 的 SSID／密碼** → 重燒（**固定 AP 或熱點都要改**） |
| Kali 攻擊用的 SSID | **`export NIDS_SSID=...`**（與 net_config 一致；預設腳本為 `302`） |
| Kali label（讀 `live_state.json` 的 `label_host`） | VMware host-only **子網**（各人可能不同） |
| `COLLECTOR_FALLBACK_IP` 維持 `""` | discovery 失敗才填**自己的** collector Wi‑Fi IP |
| Mode P：`live_state.json` 在 Pi 上 | Kali 攻擊前 **`./scripts/nids-sync.sh`**（見 §3） |

細節表見 `note/note.md` §2.0。

**Kali / Pi 第一次 `git clone` 或 `git pull` 後必做一次：**

```bash
chmod +x host/attacks/*.sh scripts/*.sh
```

否則 `sudo ./host/attacks/prepare_wifi.sh` 可能出現 `command not found`。  
（也可用 `sudo bash host/attacks/prepare_wifi.sh monitor` 繞過。）

---

## 1. 先選今天的模式（你有沒有 Raspberry Pi）

| 模式 | Collector 在哪 | 適合 |
|------|----------------|------|
| **W — Windows** | Windows | **組員預設**；沒 Pi；做 AP 上的 ARP / AUTH / probe 煙測 |
| **P — Pi** | 樹莓派 | 正式收一場：NORMAL + Deauth + SYN + ARP（中間穿 NORMAL） |
| **S — Serial** | Windows USB 序列埠 | 沒 Pi 又要穩收含 deauth 的場次 |

**組員若沒有 Pi，先看模式 W；模式 P 當附錄。**  
下面先寫 **W**，再寫 **P**；**S** 在文末。

---

## 2. 各腳本是什麼？

| 名稱 | 做什麼 | 誰跑 | 何時 |
|------|--------|------|------|
| `session_windows.ps1` | Windows 開 collector（內部叫 `bringup.py`） | Windows | 模式 W |
| `host/collector/nids_collector.py` | 真正收 syslog 的程式 | **Pi 或 Windows** | 實驗期間一直開 |
| `bringup.sh` | （可選）Pi/Linux 包裝：印說明 + 啟動 collector | Pi | 等效於直接跑 collector |
| `print_live_targets.ps1` / `.sh` | 印 Kali 用的 `export` | Win 或 Pi | 攻擊前（可選） |
| `nids-sync.sh` | 從 Pi **scp** `live_state.json` 到 Kali | Kali | Mode P 攻擊前 |
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

## 3. 模式 W — Windows 當 Collector

> **這是組員預設模式。**  
> AP 場地做 ARP / AUTH / probe 煙測，先照這段跑；Pi 不需要。

| 機器 | 要開的 |
|------|--------|
| **Windows** | `.\scripts\session_windows.ps1` + ESP32 flash/monitor |
| **Kali** | `export NIDS_SSID=...` + `prepare_wifi` + 攻擊 `.sh` |
| **Pi** | 不需要 |

```text
① AP／熱點（SSID 對齊 net_config.h；固定 AP 盡量關 client isolation）
② Windows：ESP32 flash monitor
③ Windows：.\scripts\session_windows.ps1
④ （可選）.\scripts\print_live_targets.ps1
⑤ Kali：export NIDS_SSID=<SSID>
⑥ Kali：先收 2–3 分鐘 IDLE，再打攻擊
⑦ 收工後可跑 aggregate → analyze_and_train
```

**常見煙測順序（每次只打一種）：**

```text
IDLE 3 min
→ ARP：managed → arpspoof.sh → IDLE 2 min
→ 或 AUTH：monitor → attack_auth_flood.sh → managed → IDLE 2 min
→ 或 PROBE：monitor → attack_probe_flood.sh → managed → IDLE 2 min
```

不要同時再開 `bringup.py`（`session_windows` 已會叫它）。

---

## 4. 模式 P — Pi 收資料

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
     sudo -E ./host/attacks/prepare_wifi.sh monitor
     # 腳本會：ping label host（不通則試補 Mode P 路由）、短 airodump 刷新 BSSID/CH
     # 可選強制：export NIDS_BSSID=… NIDS_WIFI_CHANNEL=…
     sudo -E ./host/attacks/attack_deauth.sh
     → collector 要有 START/STOP；等 ESP32 重連、syslog 又穩定
⑦ 再收 1–2 分鐘 NORMAL
⑧ SYN：
     sudo -E ./host/attacks/prepare_wifi.sh managed
     # 確認已連 AP（nmcli）；必要時手動 nmcli device wifi connect …
     sudo -E ./host/attacks/syn_flood.sh
     → collector 必須出現 ✋ ATTACK STOP（不只 Kali 印 FINISHED）
⑨ 再收 1–2 分鐘 NORMAL
⑩ ARP：sudo -E ./host/attacks/arpspoof.sh
     # 手機熱點上 gw_flip 常為 0；固定 AP 煙測見 docs/HELP.md
⑪ （可選煙測）Probe：monitor → attack_probe_flood.sh
⑫ （可選煙測）Auth：monitor → attack_auth_flood.sh（熱點上常弱）
⑬ 最後再收一段 NORMAL
⑭ Collector Ctrl+C → 保存 CSV
⑮ （可改天）aggregate_windows → analyze_and_train → flash
```

每打完一種，collector 應出現對應 `ATTACK START/STOP`（以 collector 終端為準）。

### 各攻擊前 Kali 介面

| 攻擊 | 先跑 | 網卡 |
|------|------|------|
| Deauth | `prepare_wifi.sh monitor`（缺 mon 時 deauth 會自動叫） | `wlan0mon` |
| SYN / ARP | `prepare_wifi.sh managed` + **連同一 AP** | `wlan0` managed |
| Auth / Probe flood | `prepare_wifi.sh monitor` | `wlan0mon` |

### Label / `live_state.json`（模式 P）

Collector 寫在 **Pi 本機**的 `data/live_state.json`（gitignore，不會跟 git pull）。  
Kali 攻擊前同步（**建議標準步驟**）：

```bash
export NIDS_PI_HOST=USER@PI_IP    # 例：pi@10.0.0.2
./scripts/nids-sync.sh
# 會 scp live_state 並印 export NIDS_LABEL_HOST=...
```

遠端路徑不同：`NIDS_PI_LIVE_STATE=~/path/data/live_state.json`

手動備案：

```bash
scp USER@PI_HOST:~/…/data/live_state.json data/live_state.json
export NIDS_LABEL_HOST=<Pi eth0 IP>
```

沒同步就手填 `NIDS_ESP32_MAC` + `NIDS_LABEL_HOST` 也可以。

**`sudo` 會清掉環境變數**：若剛 `export` 過，攻擊／prepare 請用 `sudo -E`，否則只靠 `live_state.json` 裡的欄位（且 host-only 走腳本預設）。

```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_deauth.sh
```

### Kali：SSH 還是視窗？

- 第一次接網卡／切 monitor：VMware **直接開**
- 之後：SSH 也可

---

## 5. 模式 S — 沒 Pi 的 deauth（USB 序列埠）

```text
① 韌體 SYSlOG_MODE=2，重新 flash
② Windows：python scripts/serial_collector.py --port COMx
③ Kali：label 打到跑 serial collector 的那台（常見 VMnet1 host）
④ 攻擊 deauth
```

---

## 6. Kali 最小指令（模式 W 先看）

```bash
cd /path/to/repo
chmod +x host/attacks/*.sh scripts/*.sh   # clone / pull 後做一次

# 攻擊前要有目標：collector 已收過 syslog（live_state 有 esp32_mac）。
# 模式 W 直接讀本機 live_state；模式 P 再額外 nids-sync。有 export 時下面一律 sudo -E

# --- Deauth ---
sudo -E ./host/attacks/prepare_wifi.sh monitor
# auto: label-host ping + short airodump（約 10s）→ BSSID/CH；失敗會送 STOP
sudo -E ./host/attacks/attack_deauth.sh

# --- SYN / ARP（managed + 連 AP）---
sudo -E ./host/attacks/prepare_wifi.sh managed
sudo -E ./host/attacks/syn_flood.sh
sudo -E ./host/attacks/arpspoof.sh

# --- 煙測（可選；AUTH/ARP 在固定 AP 見 docs/HELP.md）---
sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_auth_flood.sh
sudo -E ./host/attacks/attack_probe_flood.sh
```

同一時間 **只跑一支** 攻擊腳本。

`prepare_wifi.sh`：開 `wlan0mon`、設 channel、把 host-only 設成 VMnet1 位址（預設 `192.168.124.50/24`），並在 Mode P 常見拓撲下補 `10.0.0.0/24 via 192.168.124.1`。  
`attack_deauth.sh`：攻擊前檢查 label host 可 ping；預設短 airodump 刷新 BSSID／channel；失敗會送 STOP。  
若你的 VMware 是別的子網（例如舊的 `.220.x`），設 `NIDS_HOSTONLY_IP=...`；介面名不同則 `NIDS_HOSTONLY_IFACE=...`。

手機熱點常換 BSSID／頻道，且 **client isolation 會讓 ARP 煙測失敗** → 固定 AP 請關隔離；腳本預設以 **當場 airodump** 刷新 BSSID／CH。  
仍失敗時可手動：`sudo airodump-ng wlan0mon --essid <SSID>` 後 `export NIDS_BSSID=… NIDS_WIFI_CHANNEL=…`。  
Label 目標看 `live_state.label_host`：**Mode W／S** 常為 Windows `192.168.124.1`；**Mode P** 常為 Pi `10.0.0.2`（自動補 `10.0.0.0/24` 路由僅在 label host 為 `10.0.0.*` 時觸發）。

---

## 7. VMware 網卡（常踩雷）

| 網卡 | 建議 | 用途 |
|------|------|------|
| NIC1 | Host-only（VMnet1） | SSH、（模式 W）label |
| NIC2 | NAT（可選） | Kali 上網 / git |
| USB Wi-Fi | 傳給 VM | 空中攻擊 |

腳本預設對齊常見 VMnet1：`192.168.124.0/24`（Kali `.50`、Windows host `.1`）。  
若 `ipconfig` 看到的是別的網段，用環境變數覆寫；模式 P 的 label 仍以 Pi IP 為準（**`./scripts/nids-sync.sh`** / `NIDS_LABEL_HOST`）。

Mode P 若 Pi eth0 不在 VMnet1 上（例如另接 Windows `10.0.0.x`），見上方「Mode P 常見網路落差」。

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
| `docs/HELP.md` | **組員 AP 場地 ARP/AUTH 煙測任務** |
| `note/private/` | 個人備忘（gitignore） |

### 常見聯調注意（收資料前）

- 同一台機器不要開兩個 collector（`:1514` Address already in use）
- Monitor 上 `Syslog UDP → …`／collector 有刷行，再開始打攻擊
- 板上舊模型可能一直 `[INFERENCE] attack`：收資料時保持 `HIPS_ENABLE 0`；重訓後再開
- Syslog 若約 `255B` 且 parse 失敗：韌體 buffer 過舊，需 flash 含較大 syslog buffer 的版本
- Kali 印 `ATTACK FINISHED` 但 collector 沒有 `ATTACK STOP`：先確認 label IP／路由；SYN 高流量時請用新版 collector（會穿插讀 `:9999`）
- Deauth `No such BSSID`：新腳本會自動重掃；仍失敗再手 export。勿只信過期 `live_state.ap_bssid`
- 攻擊前 `label host unreachable`：Mode P 查到 Pi 路由；Mode W／S 查 VMnet1 上的 Windows 是否開著 collector
- `prepare_wifi managed` 後連不上 AP：`nmcli device wifi connect <SSID> ifname wlan0`
- ARP 有 label 但 CSV `gw_flip=0`：AP isolation 或 Kali 毒不到 ESP32 → 見 `docs/HELP.md`
- USB Wi-Fi 在 VM 裡不見 `wlan0`：VMware Removable Devices → Connect
