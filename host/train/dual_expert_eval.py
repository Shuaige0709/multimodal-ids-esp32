#!/usr/bin/env python3
"""
B′ offline dual-expert evaluation (not exported to MCU by default).

Expert W: nids-counts tree (HIDS + RSSI/SNR neutralized) — stable WIDS-lite
Expert H: HIDS-only shallow DT — stress / host pressure
Fusion:   pred = W OR H

Usage:
  python host/train/dual_expert_eval.py
  python host/train/dual_expert_eval.py --dataset data/windows/nids_windows_20260809_000851.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import DATA_WINDOWS, FIGURES_DIR, ensure_data_dirs  # noqa: E402
from host.train.nids_features import (  # noqa: E402
    ATTACK_TYPE_COL,
    HIDS_FEATURES,
    LABEL_COL,
    NIDS_COUNTS_FEATURES,
    RF_SOFT_FEATURES,
    WINDOW_FEATURES,
)


def _metrics(name, y_true, y_pred, y_score, attack_types):
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    try:
        auc = float(roc_auc_score(y_true, y_score))
    except ValueError:
        auc = None
    per_attack = {}
    for atype in sorted(set(attack_types)):
        if atype in ("NONE", "nan"):
            continue
        mask = attack_types == atype
        if mask.any():
            per_attack[atype] = float((y_pred[mask] == 1).mean())
    return {
        "name": name,
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": fpr,
        "auc": auc,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "cm": cm.tolist(),
        "per_attack_recall": per_attack,
    }


def _neutralize(X_tr, X_te, y_tr, names):
    X_tr = X_tr.copy()
    X_te = X_te.copy()
    fills = {}
    for name in names:
        idx = WINDOW_FEATURES.index(name)
        vals = X_tr[y_tr == 0, idx]
        fill = float(np.median(vals)) if len(vals) else 0.0
        fills[name] = fill
        X_tr[:, idx] = fill
        X_te[:, idx] = fill
    return X_tr, X_te, fills


def _busy_proxy_rate(df, pred_fn):
    """Pre-attack NORMAL dens_roll peak ±90s — same proxy as matched_load eval."""
    tcol = "window_start"
    if tcol not in df.columns:
        return None
    d = df.copy()
    d[tcol] = pd.to_datetime(d[tcol], format="ISO8601")
    if (d[LABEL_COL] == 1).sum() == 0:
        return None
    first = d.loc[d[LABEL_COL] == 1, tcol].min()
    pre = d[(d[LABEL_COL] == 0) & (d[tcol] < first)].sort_values(tcol)
    if len(pre) < 20:
        return None
    pre = pre.copy()
    pre["dens_roll"] = pre["packet_density"].rolling(20, min_periods=5).mean()
    peak_t = pre.loc[pre["dens_roll"].idxmax(), tcol]
    busy = pre[
        (pre[tcol] >= peak_t - pd.Timedelta(seconds=90))
        & (pre[tcol] <= peak_t + pd.Timedelta(seconds=90))
    ]
    if len(busy) == 0:
        return None
    pred = pred_fn(busy)
    return {
        "n": int(len(busy)),
        "peak_center": str(peak_t),
        "attack_rate": float((pred == 1).mean()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dataset",
        default=os.path.join(DATA_WINDOWS, "nids_windows_20260809_000851.csv"),
    )
    args = ap.parse_args()
    ensure_data_dirs()
    os.makedirs(FIGURES_DIR, exist_ok=True)

    df = pd.read_csv(args.dataset)
    for c in WINDOW_FEATURES:
        if c not in df.columns:
            df[c] = 0.0
    y = df[LABEL_COL].to_numpy(dtype=int)
    at = df[ATTACK_TYPE_COL].astype(str).to_numpy()
    X = df[WINDOW_FEATURES].to_numpy(dtype=float)

    idx = np.arange(len(df))
    X_tr, X_te, y_tr, y_te, at_tr, at_te, idx_tr, idx_te = train_test_split(
        X, y, at, idx, test_size=0.3, random_state=42, stratify=y
    )

    # Expert W: full layout with HIDS+RF soft neutralized (nids-counts)
    ban = list(HIDS_FEATURES) + list(RF_SOFT_FEATURES)
    Xw_tr, Xw_te, fills_w = _neutralize(X_tr, X_te, y_tr, ban)
    clf_w = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf_w.fit(Xw_tr, y_tr)
    pw = clf_w.predict(Xw_te)
    # score: attack leaf proportion via predict_proba if available
    sw = clf_w.predict_proba(Xw_te)[:, 1]

    # Expert H: HIDS columns only
    h_idx = [WINDOW_FEATURES.index(f) for f in HIDS_FEATURES]
    Xh_tr = X_tr[:, h_idx]
    Xh_te = X_te[:, h_idx]
    clf_h = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf_h.fit(Xh_tr, y_tr)
    ph = clf_h.predict(Xh_te)
    sh = clf_h.predict_proba(Xh_te)[:, 1]

    # Fusion OR (naive) and gated OR (H only if proba >= threshold)
    por = np.where((pw == 1) | (ph == 1), 1, 0)
    sor = np.maximum(sw, sh)
    h_gate = 0.85
    ph_gated = np.where(sh >= h_gate, 1, 0)
    por_g = np.where((pw == 1) | (ph_gated == 1), 1, 0)
    sor_g = np.where(pw == 1, np.maximum(sw, sh), np.where(ph_gated == 1, sh, sw))

    m_w = _metrics("Expert-W nids-counts", y_te, pw, sw, at_te)
    m_h = _metrics("Expert-H HIDS-only", y_te, ph, sh, at_te)
    m_or = _metrics("Fusion W OR H", y_te, por, sor, at_te)
    m_org = _metrics(
        f"Fusion W OR H(p>={h_gate})", y_te, por_g, sor_g, at_te
    )

    # Agreement on test
    both = int(((pw == 1) & (ph == 1)).sum())
    only_w = int(((pw == 1) & (ph == 0)).sum())
    only_h = int(((pw == 0) & (ph == 1)).sum())

    def pred_on_df(sub, which):
        Xs = sub[WINDOW_FEATURES].to_numpy(dtype=float)
        if which == "W":
            Xn = Xs.copy()
            for name, fill in fills_w.items():
                Xn[:, WINDOW_FEATURES.index(name)] = fill
            return clf_w.predict(Xn)
        if which == "H":
            return clf_h.predict(Xs[:, h_idx])
        if which == "OR":
            pw_ = pred_on_df(sub, "W")
            ph_ = pred_on_df(sub, "H")
            return np.where((pw_ == 1) | (ph_ == 1), 1, 0)
        if which == "OR_gated":
            Xn = Xs.copy()
            for name, fill in fills_w.items():
                Xn[:, WINDOW_FEATURES.index(name)] = fill
            pw_ = clf_w.predict(Xn)
            sh_ = clf_h.predict_proba(Xs[:, h_idx])[:, 1]
            return np.where((pw_ == 1) | (sh_ >= h_gate), 1, 0)
        raise ValueError(which)

    busy = {
        "W": _busy_proxy_rate(df, lambda s: pred_on_df(s, "W")),
        "H": _busy_proxy_rate(df, lambda s: pred_on_df(s, "H")),
        "OR": _busy_proxy_rate(df, lambda s: pred_on_df(s, "OR")),
        "OR_gated": _busy_proxy_rate(df, lambda s: pred_on_df(s, "OR_gated")),
    }

    # HIDS importances
    h_imp = {
        n: float(i)
        for n, i in zip(HIDS_FEATURES, clf_h.feature_importances_)
        if i > 0
    }
    w_imp = {
        n: float(i)
        for n, i in zip(WINDOW_FEATURES, clf_w.feature_importances_)
        if i > 0
    }

    out = {
        "dataset": os.path.basename(args.dataset),
        "split": {"test_size": 0.3, "random_state": 42},
        "expert_w_features": NIDS_COUNTS_FEATURES,
        "expert_h_features": HIDS_FEATURES,
        "fusion": "logical_OR_and_gated_OR",
        "h_proba_gate": h_gate,
        "note": (
            "Offline dual-expert for advisor narrative. "
            "Naive OR recovers ARP/SYN but raises FPR; gated OR is the practical path. "
            "MCU still ships nids-counts unless a gated OR is later exported."
        ),
        "models": [m_w, m_h, m_or, m_org],
        "test_attack_overlap": {
            "both_attack": both,
            "only_W": only_w,
            "only_H": only_h,
            "n_test": int(len(y_te)),
        },
        "busy_proxy_fp": busy,
        "expert_w_importances": w_imp,
        "expert_h_importances": h_imp,
        "hids_fill_for_W": fills_w,
        "attack_type_train": dict(Counter(at_tr)),
    }

    path = os.path.join(FIGURES_DIR, "dual_expert_20260809.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"Dataset: {args.dataset}")
    for m in (m_w, m_h, m_or, m_org):
        print(
            f"  {m['name']}: F1={m['f1']:.3f} FPR={m['fpr']:.3f} "
            f"rec={m['per_attack_recall']}"
        )
    print(f"  overlap: both={both} only_W={only_w} only_H={only_h}")
    for k, v in busy.items():
        if v:
            print(f"  BUSY FP [{k}]: {v['attack_rate']:.1%} (n={v['n']})")
    print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
