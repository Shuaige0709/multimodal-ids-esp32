# 任務索引（組員）

本週大方向如下。

| 誰 | 本週 |
|----|------|
| **Winston** | [`HELP_winston_idle_fa.md`](HELP_winston_idle_fa.md)（長 IDLE 誤報 + iperf busy；evil twin 已過關） |
| **HaoHao** | [`HELP_haohao_busy_normal.md`](HELP_haohao_busy_normal.md) |

舊 ARP/AUTH runbook 在本文後半，只留檔。


---

# 任務：固定 AP 上確認 ARP / AUTH 可見性

> 給 Winston 的短 runbook。**預設照模式 W（Windows collector，無 Pi）做。**  
> 完整實驗拓撲見 [`note/lab_runbook.md`](../note/lab_runbook.md)、架構見 [`note/note.md`](../note/note.md)。

## 背景（請先讀）

我們在**手機熱點**上已試過：

| 攻擊 | 手機熱點結果 | 備註 |
|------|--------------|------|
| DEAUTH | 可見 | 正式三類之一 |
| SYN_FLOOD | 部分可見 | 偏密度／HIDS |
| ARP_SPOOF | **不可見** | 空中 LLC 0/0；`gw_flip` 亦 0（隔離／毒不到 STA） |
| AUTH_FLOOD | **幾乎不可見** | `auth_packets` 幾乎平坦 |
| PROBE_FLOOD | **可見** | 2026-08-18 煙測過關；08.09 板上樹已能亮（未換新 counts） |

**請在固定 AP（非手機熱點）上重試 ARP 與 AUTH。** 若仍不可見，記成 sensor gap，不要硬重訓。

---

## 0. 前提（AP 場地）

1. **固定 AP**，盡量關 `client isolation` / `AP isolation` / guest isolation。
2. ESP32、Kali、Collector **都連同一 AP**（SSID／密碼對齊韌體）。
3. **兩條路分開查，不要用 monitor 網卡去 ping：**
   - **ARP（managed）**：Kali `wlan0` 還在 AP 上 → 可 ping ESP32 IP（`live_state.esp32_ip`）。不通先修隔離／路由。
   - **AUTH / deauth / probe（monitor）**：USB Wi-Fi 進入 monitor 後**沒有 IP**，ping 不到任何人是正常的。Label START/STOP 走 **VMnet1 / eth0 → Windows**（`live_state.label_host`，常見 `192.168.124.1`），不是走 `wlan0mon`。
4. Collector **先開**，等 syslog 有刷行、且 `data/live_state.json` 有 `esp32_ip` / `label_host`。

---

## 1. 用本 repo（`nids_esp32_project`）— 建議流程

### 1.1 換 AP（每人必做；模式 W）

| 步驟 | 誰 | 做什麼 |
|------|-----|--------|
| 1 | Windows | 改 `main/net_config.h` 的 `WIFI_SSID` / `WIFI_PASS` → `idf.py build flash` |
| 2 | Windows | 開 collector：`.\scripts\session_windows.ps1` |
| 3 | Kali | `export NIDS_SSID=<你的 AP SSID>`（與 net_config 一致） |
| 4 | Kali | `./scripts/print_live_targets.sh` 確認 `label_host`、ESP32 IP |

若你**沒有 Pi，就到這裡為止，照下面任務直接做。**  
若你**真的有 Pi 且要走模式 P**，才另外做：

```bash
export NIDS_PI_HOST=user@<Pi_IP>
./scripts/nids-sync.sh
```

Kali 每次 clone／pull 後：`chmod +x host/attacks/*.sh scripts/*.sh`

### 1.2 一場煙測時序（約 15 min）

```text
① Collector 已開；ESP32 已連 AP、有 syslog
② IDLE 3 min（不攻擊）
③ 任務 A 或 B（見下）
④ IDLE 2 min cool-down
⑤ 把 raw CSV 檔名 + 3~5 行摘要回傳
```

### 1.3 任務 A — ARP_SPOOF

- **介面**：`managed`（不是 monitor）
- **指令**：

```bash
sudo -E ./host/attacks/prepare_wifi.sh managed
# 確認已連 AP
sudo -E ./host/attacks/arpspoof.sh
```

- **看 CSV 欄位**：`attack_type=ARP_SPOOF` 段 vs 前段 IDLE  
  - `gw_mac` 有真實 MAC（不是 `-`）  
  - **`gw_flip` ≥ 1**（閘門）  
  - 可選：`win_pkts` 是否跳（次要）

### 1.4 任務 B — AUTH_FLOOD

- **介面**：`monitor`（USB Wi-Fi 注入；**不要**指望這張卡還能 ping）
- **Label**：仍走 host-only。進 monitor 前先確認：

```bash
# 在 Windows：ipconfig 看 VMnet1 /「VMware Network Adapter VMnet1」的 IPv4
# 在 Kali（eth0 還在、wlan 已 monitor 也沒差）：
ping -c 1 -I eth0 192.168.124.1    # 改成你的 Windows VMnet1 IP
export NIDS_LABEL_HOST=192.168.124.1
```

腳本若印 `label host unreachable` 就停：那是 **eth0 / 子網 / export 沒帶進 sudo**，不是 AUTH 做不了。用 `sudo -E`。

- **指令**：

```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_auth_flood.sh
sudo -E ./host/attacks/prepare_wifi.sh managed
```

- **看 CSV 欄位**：`attack_type=AUTH_FLOOD` 段 vs IDLE  
  - `subtype=AUTH` 列占比是否明顯上升  
  - 聚合後 `auth_packets` 是否非平坦（需跑 `aggregate_windows.py` 或目視 subtype）

### 1.5 交回格式（每場）

1. AP：SSID / BSSID / CH，isolation 是否關  
2. 完整命令列  
3. `data/raw/nids_dataset_*.csv` 檔名（勿 commit 大檔，用雲端／USB 傳）  
4. IDLE vs 攻擊段：上表欄位中位／占比  
5. 結論：**看得見 / 看不見** + 原因猜測  

快速自檢（本 repo CSV）：

```bash
python3 - <<'PY'
import csv, sys
from collections import Counter
p = sys.argv[1]
rows = list(csv.DictReader(open(p, encoding="utf-8")))
def is_probe(s): return (s or "").startswith("PROBE")
for at in sorted(set(r["attack_type"] for r in rows)):
    g = [r for r in rows if r["attack_type"] == at]
    if at == "ARP_SPOOF":
        fl = [int(r.get("gw_flip") or 0) for r in g]
        print(at, "n", len(g), "gw_flip max", max(fl) if fl else 0)
    elif at == "AUTH_FLOOD":
        auth = sum(1 for r in g if r.get("subtype") == "AUTH")
        print(at, "n", len(g), "AUTH rows", auth, "frac", round(auth/len(g),3) if g else 0)
    else:
        print(at, "n", len(g))
PY
data/raw/nids_dataset_XXXX.csv
```

---

## 2. 用 徐子皓的 `packet_monitor` / Guard（可選）

若你用徐子皓或你自己的韌體收資料，**同一場仍請用 Kali 的 START/STOP label**（或對齊時間戳），以方便對照。

| 本 repo 概念 | Guard 常見對應 |
|-------------|----------------|
| `subtype=DEAUTH` | `deauth_pkt` |
| `win_pkts` / 密度 | `total_pkt`、窗計數 |
| `probe_packets` | probe 相關欄 |
| ARP（我們） | `gw_flip` 或你方 ARP opcode 計數 |
| AUTH | `auth_packets` 或 EAPOL 欄 |

交回：**raw 或 cleaned windows CSV** + 同上 5 點摘要。不必先對齊我們的 `model.h`。

---

## 3. 核心問題

在**你的 AP** 上，ARP_SPOOF 與 AUTH_FLOOD 是否在感測器訊號上**非平坦**？

- **看得見** → 可列第四類候選，再談 matched-load / balance（仍不重訓直到我確認）。  
- **看不見** → 記成 observability gap；簡報寫「平台／隔離限制」，不要硬加特徵。

問題請開 issue 或私訊。  
若要 commit 結果請開 branch。
