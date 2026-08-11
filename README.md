# ESP32 Lightweight Multimodal NIDS

Edge multimodal NIDS on ESP32 (100 ms windows + on-device tree).  
**Attacks: shell only. Collector / train: Python.**

## Who runs what (no twins)

| 工作 | 指令 | 機器 |
|------|------|------|
| 開 collector（Windows） | `.\scripts\session_windows.ps1` | Windows |
| 開 collector（Pi） | `python3 host/collector/nids_collector.py` | Pi |
| 印給 Kali 的 export | `.\scripts\print_live_targets.ps1` | Windows（Pi 上可 `print_live_targets.sh`） |
| 網卡 monitor/managed | `sudo ./host/attacks/prepare_wifi.sh monitor\|managed` | Kali |
| Deauth / SYN / ARP / Auth flood | `sudo ./host/attacks/attack_*.sh` | Kali |
| 聚合 + 平衡檢查 + 訓練 | `aggregate_windows.py` → `check_dataset_balance.py` → `analyze_and_train.py` | Windows |
| Mode S（deauth 穩收） | `SYSlOG_MODE 2` + `serial_collector.py --standby` | Windows |
| 燒錄 | `idf.py build flash monitor` | Windows |

詳細步驟見 `note/lab_runbook.md`；收完用 `python host/train/check_dataset_balance.py --strict` 驗收。

## Layout

```
main/                 ESP-IDF firmware
host/collector/       nids_collector.py
host/attacks/         *.sh + netconfig.sh + prepare_wifi.sh
host/train/           aggregate / analyze (Python)
scripts/              session_windows.ps1, print_live_targets.*, bringup.*（可選包裝）
data/                 captures (mostly local); Phase A baseline CSVs are in Git — see data/README.md
note/                 note.md + lab_runbook.md
archive/              old duplicates / secrets (do not push logins)
```

## Quick examples

**Windows collector (mode W):**
```powershell
.\scripts\session_windows.ps1
.\scripts\print_live_targets.ps1
```

**Pi collector (mode P):**
```bash
python3 host/collector/nids_collector.py
# Kali: export NIDS_LABEL_HOST=<Pi_IP>
```

（`./scripts/bringup.sh` 只是可選包裝，多印幾行 checklist，不是必跑。）

**Kali attacks (one at a time; use `sudo -E` if you exported NIDS_* vars):**
```bash
sudo -E ./host/attacks/prepare_wifi.sh monitor
# Deauth on phone hotspot: airodump BSSID+channel, then export NIDS_BSSID / NIDS_WIFI_CHANNEL
sudo -E ./host/attacks/attack_deauth.sh
sudo -E ./host/attacks/prepare_wifi.sh managed   # restarts NM; join hotspot if needed
sudo -E ./host/attacks/syn_flood.sh              # confirm collector shows ATTACK STOP
sudo -E ./host/attacks/arpspoof.sh
# Phase C (after balanced baseline): sudo -E ./host/attacks/attack_auth_flood.sh
```

**Train / accept (after a balanced capture):**
```powershell
python host/train/aggregate_windows.py
python host/train/check_dataset_balance.py --strict
python host/train/analyze_and_train.py --strict-export
```

## First clone (teammates)

```bash
git clone <your-repo-url>
cd nids_esp32_project
python -m venv .venv          # recommended (Windows: py -3 -m venv .venv)
# Windows: .\.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt   # includes optional XGBoost/LightGBM for offline comparison
# Kali / Pi：每次新 clone（或 pull 後腳本仍不能 ./ 執行）都要：
chmod +x host/attacks/*.sh scripts/*.sh
```

**Train tip:** activate `.venv` before `analyze_and_train.py` so boosters appear in `model_comparison.png`. MCU export remains the shallow DecisionTree (`model.h`), not Boost.

**Network / IP（多數不用手填）：**

1. 改 `main/net_config.h` 的 `WIFI_SSID` / `WIFI_PASS` 成你們的熱點 → `idf.py flash`
2. 開 collector → ESP32 靠 discovery 找 IP（`COLLECTOR_FALLBACK_IP` 保持 `""`）
3. Kali 攻擊腳本讀 `data/live_state.json`；不通再用 `print_live_targets` 貼 `export`
4. VMware host-only 子網以**各人電腦**為準，見 `note/note.md` §2.0

- Datasets: trial captures stay local; Phase A baseline is in Git → see `data/README.md`
- Team notes: `note/lab_runbook.md`, `note/note.md`
- Do not commit `sdkconfig`, `build/`, CSV, or secrets under `archive/` / `note/private/`
