#!/usr/bin/env python3
"""Week-1 M1 offline candidate. Does not write main/model.h and must not be flashed.

Train set and holdouts: note/private/eval/dataset_manifest_20260902.md

Usage:
  python host/train/m1_offline_train.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_WINDOWS, MODEL_H, PROJECT_ROOT, ensure_data_dirs  # noqa: E402
from host.train.analyze_and_train import (  # noqa: E402
    evaluate,
    export_model_h,
    load_windows,
)
from host.train.nids_features import (  # noqa: E402
    ATTACK_TYPE_COL,
    HIDS_FEATURES,
    LABEL_COL,
    NIDS_COUNTS_FEATURES,
    RF_SOFT_FEATURES,
    WINDOW_FEATURES,
)

OUT_DIR = os.path.join(PROJECT_ROOT, "note", "private", "eval")
QUIET_TOT = 50.0
M1_POS = frozenset({"DEAUTH", "PROBE_FLOOD"})
DROP_FROM_M1 = frozenset({"SYN_FLOOD", "ARP_SPOOF", "AUTH_FLOOD", "EVIL_TWIN", "BEACON_FLOOD"})

# After first 20 min of P0 160837 the lamp was 0 (see self_week1_capture).
P0_SETTLE = datetime.fromisoformat("2026-09-02T16:28:37")


def _win(stamp):
    return os.path.join(DATA_WINDOWS, f"nids_windows_{stamp}.csv")


def _require(path):
    if not os.path.isfile(path):
        raise SystemExit(f"missing {path} — run aggregate_windows.py first")
    return path


def _fills_from_normal(X, y, names):
    fills = {}
    for name in names:
        idx = WINDOW_FEATURES.index(name)
        normal = X[y == 0, idx]
        fills[name] = float(np.median(normal)) if len(normal) else 0.0
    return fills


def _apply_fills(X, fills):
    out = X.copy()
    for name, val in fills.items():
        out[:, WINDOW_FEATURES.index(name)] = val
    return out


def _fit_dt(X, y):
    clf = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf.fit(X, y)
    return clf


def _importance(clf):
    if not hasattr(clf, "feature_importances_"):
        return {}
    pairs = sorted(
        zip(WINDOW_FEATURES, clf.feature_importances_),
        key=lambda kv: -kv[1],
    )
    return {k: float(v) for k, v in pairs if v > 1e-9}


def load_m1_train():
    parts = []
    a = load_windows(_require(_win("20260809_000851")))
    a = a[~a[ATTACK_TYPE_COL].isin(DROP_FROM_M1)].copy()
    a["_src"] = "000851"
    parts.append(a)

    b = load_windows(_require(_win("20260826_232220")))
    b = b[~b[ATTACK_TYPE_COL].isin(DROP_FROM_M1)].copy()
    b["_src"] = "232220"
    parts.append(b)

    c = load_windows(_require(_win("20260818_234622")))
    keep = (
        c[ATTACK_TYPE_COL].isin(M1_POS)
        | (
            (c[ATTACK_TYPE_COL] == "NONE")
            & (c["total_packets"] < QUIET_TOT)
        )
    )
    c = c.loc[keep].copy()
    c["_src"] = "234622_filtered"
    parts.append(c)

    df = pd.concat(parts, ignore_index=True)
    # Safety: only DEAUTH/PROBE as positives
    pos = df[ATTACK_TYPE_COL].isin(M1_POS)
    df.loc[~pos, LABEL_COL] = 0
    df.loc[pos, LABEL_COL] = 1
    df.loc[~pos, ATTACK_TYPE_COL] = df.loc[~pos, ATTACK_TYPE_COL].where(
        df.loc[~pos, ATTACK_TYPE_COL] == "NONE", "NONE"
    )
    return df


def load_m0_train():
    df = load_windows(_require(_win("20260809_000851")))
    df["_src"] = "000851"
    return df


def holdout_slice(df, settle_only=False):
    if not settle_only or "window_start" not in df.columns:
        return df
    ts = pd.to_datetime(df["window_start"], errors="coerce")
    return df.loc[ts >= P0_SETTLE].copy()


def window_stats(clf, df, fills=None, settle_only=False):
    df = holdout_slice(df, settle_only=settle_only)
    if df.empty:
        return {"n": 0}
    X = df[WINDOW_FEATURES].to_numpy(dtype=float)
    if fills:
        X = _apply_fills(X, fills)
    y = df[LABEL_COL].to_numpy(dtype=int)
    at = df[ATTACK_TYPE_COL].astype(str).to_numpy()
    pred = clf.predict(X)
    none = at == "NONE"
    n_none = int(none.sum())
    fp = int(((pred == 1) & none).sum())
    edges = 0
    prev = 0
    for p, nflag in zip(pred, none):
        cur = 1 if (p == 1 and nflag) else 0
        if cur and not prev:
            edges += 1
        prev = cur
    per = {}
    for name in sorted(set(at)):
        if name in ("NONE", "", "nan"):
            continue
        mask = at == name
        per[name] = {
            "n": int(mask.sum()),
            "recall": float((pred[mask] == 1).mean()) if mask.any() else None,
        }
    hours = n_none * 0.1 / 3600.0
    return {
        "n": int(len(df)),
        "n_none": n_none,
        "none_fp_windows": fp,
        "none_window_fpr": (fp / n_none) if n_none else None,
        "none_rising_edges": edges,
        "none_hours_occupied_bins": hours,
        "per_attack": per,
        "pred_rate": float((pred == 1).mean()),
    }


def variant_spec(name):
    if name == "full":
        return []
    if name == "no-heap":
        return ["heap"]
    if name == "nids-only":
        return list(HIDS_FEATURES)
    if name == "nids-counts":
        return list(HIDS_FEATURES) + list(RF_SOFT_FEATURES)
    raise ValueError(name)


def train_variant(df, name):
    X = df[WINDOW_FEATURES].to_numpy(dtype=float)
    y = df[LABEL_COL].to_numpy(dtype=int)
    at = df[ATTACK_TYPE_COL].astype(str).to_numpy()
    ban = variant_spec(name)
    fills = _fills_from_normal(X, y, ban) if ban else {}
    X_fit = _apply_fills(X, fills) if fills else X
    clf = _fit_dt(X_fit, y)
    # in-dataset split for the report (not used for the exported tree)
    try:
        X_tr, X_te, y_tr, y_te, at_tr, at_te = train_test_split(
            X_fit, y, at, test_size=0.3, random_state=42, stratify=y
        )
        split_clf = _fit_dt(X_tr, y_tr)
        split = evaluate(f"M1 {name} in-dataset 30%", split_clf, X_te, y_te, at_te)
        split.pop("y_pred", None)
        split.pop("y_score", None)
        split.pop("cm", None)
        split.pop("report", None)
    except ValueError:
        split = {"error": "stratify failed"}
    return {
        "clf": clf,
        "fills": fills,
        "importances": _importance(clf),
        "tree_text": export_text(clf, feature_names=WINDOW_FEATURES, max_depth=4),
        "in_dataset": split,
        "counts_features_used": NIDS_COUNTS_FEATURES if name == "nids-counts" else None,
    }


def main():
    ensure_data_dirs()
    if not os.path.isfile(MODEL_H):
        raise SystemExit("main/model.h missing; abort so we cannot clobber a board file later")

    m0_df = load_m0_train()
    m1_df = load_m1_train()
    print("M0 train", len(m0_df), Counter(m0_df[ATTACK_TYPE_COL]))
    print("M1 train", len(m1_df), Counter(m1_df[ATTACK_TYPE_COL]), "pos", int(m1_df[LABEL_COL].sum()))

    holdouts = {}
    for stamp, tag in (
        ("20260827_010524", "holdout_event"),
        ("20260902_160837", "holdout_fpr"),
        ("20260830_233008", "holdout_domain"),
        ("20260826_232220", "seen_hotspot_deauth"),
    ):
        path = _win(stamp)
        if os.path.isfile(path):
            holdouts[tag] = load_windows(path)
            holdouts[tag]["_src"] = stamp
            print("holdout", tag, stamp, len(holdouts[tag]), Counter(holdouts[tag][ATTACK_TYPE_COL]))
        else:
            print("skip missing holdout", path)

    m0_pack = train_variant(m0_df, "nids-counts")
    m0_pack["role"] = "M0_replay_nids_counts_on_000851"

    m1_packs = {}
    for name in ("full", "no-heap", "nids-only", "nids-counts"):
        print("fit M1", name)
        m1_packs[name] = train_variant(m1_df, name)

    def eval_all(pack):
        out = {}
        for tag, hdf in holdouts.items():
            out[tag] = window_stats(pack["clf"], hdf, fills=pack["fills"])
        if "holdout_fpr" in holdouts:
            out["holdout_fpr_after20min"] = window_stats(
                pack["clf"], holdouts["holdout_fpr"], fills=pack["fills"], settle_only=True
            )
        return out

    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "board_model_h_untouched": os.path.abspath(MODEL_H),
        "m0_train_n": int(len(m0_df)),
        "m0_train_types": dict(Counter(m0_df[ATTACK_TYPE_COL])),
        "m1_train_n": int(len(m1_df)),
        "m1_train_types": dict(Counter(m1_df[ATTACK_TYPE_COL])),
        "m1_train_pos": int(m1_df[LABEL_COL].sum()),
        "m0": {
            "in_dataset": m0_pack["in_dataset"],
            "importances": m0_pack["importances"],
            "tree_text": m0_pack["tree_text"],
            "holdout": eval_all(m0_pack),
        },
        "m1": {},
        "promotion": {},
    }
    for name, pack in m1_packs.items():
        report["m1"][name] = {
            "in_dataset": pack["in_dataset"],
            "importances": pack["importances"],
            "tree_text": pack["tree_text"],
            "holdout": eval_all(pack),
            "neutralized": list(pack["fills"]),
        }

    # Promotion vs M0 replay using nids-counts (same family as board)
    m1c = report["m1"]["nids-counts"]["holdout"]
    m0h = report["m0"]["holdout"]

    def rec(block, attack):
        st = (block.get("holdout_event") or {}).get("per_attack") or {}
        return (st.get(attack) or {}).get("recall")

    def fpr(block, key):
        return (block.get(key) or {}).get("none_window_fpr")

    report["promotion"] = {
        "compare": "M1 nids-counts vs M0-replay nids-counts (not live OLED)",
        "deauth_recall_m0": rec(m0h, "DEAUTH"),
        "deauth_recall_m1": rec(m1c, "DEAUTH"),
        "probe_recall_m0": rec(m0h, "PROBE_FLOOD"),
        "probe_recall_m1": rec(m1c, "PROBE_FLOOD"),
        "fpr_160837_m0": fpr(m0h, "holdout_fpr"),
        "fpr_160837_m1": fpr(m1c, "holdout_fpr"),
        "fpr_160837_settle_m0": fpr(m0h, "holdout_fpr_after20min"),
        "fpr_160837_settle_m1": fpr(m1c, "holdout_fpr_after20min"),
        "fpr_huang_m0": fpr(m0h, "holdout_domain"),
        "fpr_huang_m1": fpr(m1c, "holdout_domain"),
        "flash": False,
        "reason": None,
    }
    p = report["promotion"]
    ok_deauth = (p["deauth_recall_m1"] is not None and p["deauth_recall_m0"] is not None
                 and p["deauth_recall_m1"] >= p["deauth_recall_m0"] - 0.05)
    ok_probe = (p["probe_recall_m1"] is not None and p["probe_recall_m0"] is not None
                and p["probe_recall_m1"] >= p["probe_recall_m0"] - 0.05)
    def not_worse(a, b, slack=0.0):
        if a is None or b is None:
            return False
        return a <= b + slack
    ok_fpr = not_worse(p["fpr_160837_settle_m1"], p["fpr_160837_settle_m0"], slack=0.0) and not_worse(
        p["fpr_huang_m1"], p["fpr_huang_m0"], slack=0.02
    )
    p["pass_event"] = bool(ok_deauth and ok_probe)
    p["pass_fpr"] = bool(ok_fpr)
    p["promote_to_flash"] = False
    if p["pass_event"] and p["pass_fpr"]:
        p["reason"] = "holdout not worse; still no flash this week - needs board smoke later"
    else:
        p["reason"] = "do not flash: event recall or cross-domain FPR not improved enough vs M0 replay"

    cand_h = os.path.join(OUT_DIR, "m1_nids_counts.candidate.h")
    export_model_h(m1_packs["nids-counts"]["clf"], WINDOW_FEATURES, cand_h)
    # Confirm board header unchanged by export target
    report["candidate_header"] = cand_h
    report["board_model_h_still"] = os.path.abspath(MODEL_H)

    json_path = os.path.join(OUT_DIR, "m1_offline_20260902.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("wrote", json_path)
    print("wrote", cand_h)
    print("promotion", report["promotion"])
    print("board model.h must remain 2026-08-09 — not overwritten")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
