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

**Kali attacks (one at a time):**
```bash
sudo ./host/attacks/prepare_wifi.sh monitor
sudo ./host/attacks/attack_deauth.sh
sudo ./host/attacks/prepare_wifi.sh managed   # then join hotspot
sudo ./host/attacks/syn_flood.sh
sudo ./host/attacks/arpspoof.sh
```

## First clone (teammates)

```bash
git clone <your-repo-url>
cd nids_esp32_project
pip install -r requirements.txt
chmod +x scripts/*.sh host/attacks/*.sh   # on Kali / Pi
```

- Datasets are **not** in Git → see `data/README.md` (Google Drive)
- Team notes: `note/lab_runbook.md` (how to run a lab), `note/note.md` (design)
- Do not commit `sdkconfig`, `build/`, CSV, or anything under `archive/` except the README stubs

```bash
pip install -r requirements.txt          # already noted above
chmod +x scripts/*.sh host/attacks/*.sh  # Kali / Pi
```
