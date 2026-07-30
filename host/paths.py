"""
Shared filesystem paths for host-side tools.

All scripts should import from here so collector / attacks / train agree on
where datasets, live_state.json, and model.h live — independent of CWD.
"""
from __future__ import annotations

import os

# host/paths.py -> host/ -> project root
HOST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HOST_DIR)

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DATA_RAW = os.path.join(DATA_DIR, "raw")
DATA_WINDOWS = os.path.join(DATA_DIR, "windows")

# Runtime state written by the collector; read by attack scripts
LIVE_STATE_FILE = os.path.join(DATA_DIR, "live_state.json")

# Firmware model header exported by analyze_and_train.py
MODEL_H = os.path.join(PROJECT_ROOT, "main", "model.h")

# Paper / report figures (kept inside the repo under docs/)
FIGURES_DIR = os.path.join(PROJECT_ROOT, "docs", "figures")

DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")


def ensure_data_dirs():
    os.makedirs(DATA_RAW, exist_ok=True)
    os.makedirs(DATA_WINDOWS, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)
