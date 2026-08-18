# ESP32 Lightweight Multimodal NIDS

Edge multimodal NIDS on ESP32 (100 ms windows + on-device tree).  
**Attacks: shell only. Collector / train: Python.**

**Winston 任務：** [`docs/HELP.md`](docs/HELP.md)  
**實驗日步驟：** [`note/lab_runbook.md`](note/lab_runbook.md)

## Who runs what (no twins)

| 工作 | 指令 | 機器 |
|------|------|------|
| 開 collector（Windows） | `.\scripts\session_windows.ps1` | Windows |
| 開 collector（Pi） | `python3 host/collector/nids_collector.py` | Pi |
| Kali 同步 live_state（Mode P） | `./scripts/nids-sync.sh` | Kali |
| 印給 Kali 的 export | `./scripts/print_live_targets.sh` | Kali / Pi / Win |
| 網卡 monitor/managed | `sudo ./host/attacks/prepare_wifi.sh monitor\|managed` | Kali |
| Deauth / SYN / ARP / Probe / Auth | `sudo -E ./host/attacks/*.sh` | Kali |
| 聚合 + 平衡檢查 + 訓練 | `aggregate_windows.py` → `check_dataset_balance.py` → `analyze_and_train.py` | Windows |
| Mode S（deauth 穩收） | `SYSlOG_MODE 2` + `serial_collector.py --standby` | Windows |
| 燒錄 | `idf.py build flash monitor` | Windows |

收完用 `python host/train/check_dataset_balance.py --strict` 驗收。

## Attack visibility (smoke tests — not train gates yet)

| Attack | Phone hotspot (tried) | Fixed AP |
|--------|----------------------|----------|
| DEAUTH | OK | OK expected |
| SYN_FLOOD | partial (density/HIDS) | OK expected |
| ARP_SPOOF | **fail** (`gw_flip` stays 0) | **needs retest** — see HELP.md |
| AUTH_FLOOD | **weak** (`auth_packets` flat) | **needs retest** — see HELP.md |
| PROBE_FLOOD | **pass** (2026-08-18 smoke) | not re-validated |

Do not treat ARP/AUTH as a fourth class on hotspot data. Teammates with a real AP: follow [`docs/HELP.md`](docs/HELP.md).

## Layout

```
main/                 ESP-IDF firmware
host/collector/       nids_collector.py
host/attacks/         *.sh + netconfig.sh + prepare_wifi.sh
host/train/           aggregate / analyze (Python)
scripts/              session_windows.ps1, nids-sync.sh, print_live_targets.*
docs/                 HELP.md (teammate tasks), reports
data/                 captures (mostly local); Phase A baseline in Git — see data/README.md
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
# Kali (after collector has syslog):
export NIDS_PI_HOST=user@10.0.0.2
./scripts/nids-sync.sh
```

**Kali attacks** (one at a time; **`sudo -E`** if you exported `NIDS_*`):
```bash
chmod +x host/attacks/*.sh scripts/*.sh   # after clone/pull

sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_deauth.sh

sudo -E ./host/attacks/prepare_wifi.sh managed   # join your AP (SSID = net_config.h)
sudo -E ./host/attacks/syn_flood.sh
sudo -E ./host/attacks/arpspoof.sh              # ARP: managed; gate = gw_flip in CSV

sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_auth_flood.sh     # AUTH: monitor

sudo -E ./host/attacks/prepare_wifi.sh monitor
sudo -E ./host/attacks/attack_probe_flood.sh    # smoke only until visibility OK
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
pip install -r requirements.txt
chmod +x host/attacks/*.sh scripts/*.sh
```

**Train tip:** activate `.venv` before `analyze_and_train.py`. MCU export is shallow DecisionTree (`model.h`), not XGB/LGBM.

### Switching to your own AP (not phone hotspot)

1. Edit `main/net_config.h` → `WIFI_SSID` / `WIFI_PASS` → **`idf.py build flash`**
2. On Kali: **`export NIDS_SSID=<same SSID>`** (default in `netconfig.sh` is `302`)
3. Start collector → wait for syslog + `data/live_state.json`
4. Mode P only: **`./scripts/nids-sync.sh`** from Kali (copies live_state, prints `NIDS_LABEL_HOST`)
5. If AP has **client isolation**: ARP spoof and UDP syslog may fail — disable isolation or use Mode S (serial)

**Network / IP (usually no manual IP):**

1. Collector discovery on UDP `:5005`; keep `COLLECTOR_FALLBACK_IP` as `""` in firmware unless debugging
2. Kali reads `data/live_state.json`; override with `export NIDS_LABEL_HOST=...` if needed
3. VMware host-only subnet is **per machine** — see `note/note.md` §2.0

- Datasets: trial captures stay local; Phase A baseline in Git → `data/README.md`
- Team notes: `note/lab_runbook.md`, `note/note.md`, teammate AP tasks → **`docs/HELP.md`**
- Do not commit `sdkconfig`, `build/`, trial CSVs, or secrets under `archive/` / `note/private/`
