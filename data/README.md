# Data directory

CSV datasets are **not tracked by Git**. Keep captures on your machine and share
large / final datasets via **Google Drive** (link the Drive folder in the team chat
or paste the URL below).

## Layout

| Path | Contents |
|------|----------|
| `raw/` | Per-packet captures from `host/collector/nids_collector.py` (`nids_dataset_*.csv`) |
| `windows/` | 100 ms aggregated features from `host/train/aggregate_windows.py` |
| `live_state.json` | Runtime only (ESP32 IP/MAC); gitignored |

## Suggested Drive layout

```
NIDS-shared/
  raw/
  windows/
  models/          # optional copies of model.h for a given experiment
  NOTES.md         # which capture corresponds to which attack / venue
```

When a Drive dataset is ready for training:

```bash
# download into local folders, then:
python host/train/aggregate_windows.py data/raw/<file>.csv
python host/train/analyze_and_train.py
```

## Google Drive link (fill in)

- Team dataset folder: _TODO — paste URL here_
