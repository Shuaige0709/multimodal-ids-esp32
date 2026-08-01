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
| Deauth / SYN / ARP | `sudo ./host/attacks/attack_deauth.sh` 等 | Kali |
| 聚合 + 訓練 | `python host/train/aggregate_windows.py` → `analyze_and_train.py` | Windows |
| 燒錄 | `idf.py build flash monitor` | Windows |

詳細步驟見 `note/lab_runbook.md`。

## Layout

```
main/                 ESP-IDF firmware
host/collector/       nids_collector.py
host/attacks/         *.sh + netconfig.sh + prepare_wifi.sh
host/train/           aggregate / analyze (Python)
scripts/              session_windows.ps1, print_live_targets.*, bringup.*（可選包裝）
data/                 local CSV (gitignored) → Google Drive for sharing
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
sudo -E ./host/attacks/attack_deauth.sh
sudo -E ./host/attacks/prepare_wifi.sh managed   # then join hotspot
sudo -E ./host/attacks/syn_flood.sh
sudo -E ./host/attacks/arpspoof.sh
```

## First clone (teammates)

```bash
git clone <your-repo-url>
cd nids_esp32_project
pip install -r requirements.txt
# Kali / Pi：每次新 clone（或 pull 後腳本仍不能 ./ 執行）都要：
chmod +x host/attacks/*.sh scripts/*.sh
```

**Network / IP（多數不用手填）：**

1. 改 `main/net_config.h` 的 `WIFI_SSID` / `WIFI_PASS` 成你們的熱點 → `idf.py flash`
2. 開 collector → ESP32 靠 discovery 找 IP（`COLLECTOR_FALLBACK_IP` 保持 `""`）
3. Kali 攻擊腳本讀 `data/live_state.json`；不通再用 `print_live_targets` 貼 `export`
4. VMware host-only 子網以**各人電腦**為準，見 `note/note.md` §2.0

- Datasets are **not** in Git → see `data/README.md`
- Team notes: `note/lab_runbook.md`, `note/note.md`
- Do not commit `sdkconfig`, `build/`, CSV, or secrets under `archive/` / `note/private/`
