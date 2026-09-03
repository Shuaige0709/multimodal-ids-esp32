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

## Density / subtype contract (`win_*`)

Firmware syslog may include `win_pkts` / `win_dens` (on-device 100 ms window totals)
and `win_deauth` / `win_probe` / `win_beacon` / `win_auth` (same window, same
semantics). Collector writes them to raw CSV. `aggregate_windows.py` prefers them
for `total_packets` / `packet_density` and for the existing subtype columns
(`deauth_packets`, `probe_packets`, `beacon_packets`, `auth_packets`). Sidecar
`win_bssid` / `win_twin` / `win_rogue` aggregate as `unique_bssid` / `twin_bssid` /
`rogue_seen` (not `WINDOW_FEATURES` / `model.h`).

**Frame-composition sidecars** (2026-09-03+, syslog only until ablation):

`win_mgmt` / `win_data` / `win_ctrl` / `win_bytes` / `win_len_mean` /
`win_len_max` / `win_mgmt_bytes` / `win_data_bytes` → raw CSV columns.
`aggregate_windows.py` maps them to `mgmt_packets`, `data_packets`, … and
derived ratios (`mgmt_ratio`, `data_ratio`, `bytes_per_pkt`, subtype ratios).
These are **sidecar / offline ablation only** — not in `model.h` until promoted.

Older captures without those fields still aggregate via CSV row / subtype counts and
print a WARN (thinned syslog ≠ air). Do **not** add new `WINDOW_FEATURES` names
for sidecar counters — they stay outside the 17-column model contract.

## New captures (not the baseline)

1. Collect → `data/raw/nids_dataset_*.csv` (stays local / untracked)
2. Aggregate → `data/windows/…`
3. If a run becomes a **new locked baseline**, add an exception in `.gitignore` (same pattern as above) and commit those two CSVs + update this README.

Do **not** commit trial dumps, failed sessions, or `live_state.json`.

## Which local CSVs matter?

Active set only in `raw/` + `windows/` (6 captures).  
Everything else moved to `data/archive/` (see `data/archive/README.md`).  
Personal index / plan: `note/private/README.md`.  
Current training candidate (not Git-locked): `20260809_000851` (matched-load).
