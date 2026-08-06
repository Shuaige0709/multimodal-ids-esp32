# Data directory

Most captures stay **local** (gitignored).  
**Phase A locked baseline** is tracked in Git so anyone can reproduce the reported metrics.

## Layout

| Path | Contents | Git |
|------|----------|-----|
| `raw/` | Per-packet captures (`nids_dataset_*.csv`) | ignored, except baseline below |
| `windows/` | 100 ms features (`nids_windows_*.csv`) | ignored, except baseline below |
| `live_state.json` | Runtime ESP32 IP/MAC | always ignored |
| `README.md` | this file | tracked |

## Tracked baseline (Phase A)

| File | Role |
|------|------|
| `raw/nids_dataset_20260805_003226.csv` | Labeled capture (START/STOP clean) |
| `windows/nids_windows_20260805_003226.csv` | Aggregated 100 ms windows used for eval |

Reproduce:

```bash
python host/train/check_dataset_balance.py --dataset data/windows/nids_windows_20260805_003226.csv --strict
python host/train/analyze_and_train.py --dataset data/windows/nids_windows_20260805_003226.csv
```

To rebuild windows from raw:

```bash
python host/train/aggregate_windows.py data/raw/nids_dataset_20260805_003226.csv
```

## Density contract (win_pkts / win_dens)

Firmware syslog may include `win_pkts` / `win_dens` (on-device 100 ms window totals).  
Collector writes them to raw CSV; `aggregate_windows.py` prefers them for
`total_packets` / `packet_density`. Older captures without those fields still
aggregate via CSV row count and print a WARN (thinned syslog ≠ air).

## New captures (not the baseline)

1. Collect → `data/raw/nids_dataset_*.csv` (stays local / untracked)
2. Aggregate → `data/windows/…`
3. If a run becomes a **new locked baseline**, add an exception in `.gitignore` (same pattern as above) and commit those two CSVs + update this README.

Do **not** commit trial dumps, failed sessions, or `live_state.json`.
