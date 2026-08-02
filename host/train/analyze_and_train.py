#!/usr/bin/env python3
"""
analyze_and_train.py - multimodal NIDS evaluation + m2cgen model export.

Trains on 100 ms window features (nids_windows_*.csv) by default, reports
trustworthy metrics (F1 / Recall / AUC, not just accuracy), compares models,
runs a fusion ablation (full multimodal vs NIDS-only), and exports the chosen
decision tree to main/model.h via m2cgen for on-device inference.

Usage:
  python host/train/aggregate_windows.py
  python host/train/analyze_and_train.py
  python host/train/analyze_and_train.py --dataset data/windows/nids_windows_....csv
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import warnings
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import m2cgen as m2c
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from host.paths import (  # noqa: E402
    DATA_WINDOWS, FIGURES_DIR, MODEL_H, ensure_data_dirs,
)
from host.train.nids_features import (  # noqa: E402
    ATTACK_TYPE_COL,
    HIDS_FEATURES,
    LABEL_COL,
    MAX_HEAP_IMPORTANCE,
    NIDS_BASELINE_FEATURES,
    NIDS_ONLY_FEATURES,
    WIDS_P0_FEATURES,
    WINDOW_FEATURES,
)

warnings.filterwarnings("ignore", category=UserWarning)

ensure_data_dirs()
OUTPUT_DIR = FIGURES_DIR
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Optional boosters — degrade gracefully if not installed.
OPTIONAL_MODELS = {}
try:
    from xgboost import XGBClassifier  # type: ignore

    OPTIONAL_MODELS["XGBoost"] = lambda: XGBClassifier(
        n_estimators=80, max_depth=4, learning_rate=0.1,
        eval_metric="logloss", random_state=42,
    )
except ImportError:
    pass
try:
    from lightgbm import LGBMClassifier  # type: ignore

    OPTIONAL_MODELS["LightGBM"] = lambda: LGBMClassifier(
        n_estimators=80, max_depth=4, learning_rate=0.1,
        random_state=42, verbose=-1,
    )
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def find_default_dataset():
    windows = sorted(glob.glob(os.path.join(DATA_WINDOWS, "nids_windows_*.csv")))
    if windows:
        return windows[-1]
    raise SystemExit(
        f"No nids_windows_*.csv found in {DATA_WINDOWS}. "
        "Run: python host/train/aggregate_windows.py"
    )


def load_windows(path):
    import pandas as pd

    df = pd.read_csv(path)
    # Older window CSVs may lack P0 WIDS columns — fill with 0 for forward compat.
    for c in WINDOW_FEATURES:
        if c not in df.columns:
            df[c] = 0.0
    if LABEL_COL not in df.columns:
        raise SystemExit(f"Dataset missing label column: {LABEL_COL}")
    if ATTACK_TYPE_COL not in df.columns:
        df[ATTACK_TYPE_COL] = "NONE"
    df[LABEL_COL] = (df[LABEL_COL].astype(float) > 0).astype(int)
    for c in WINDOW_FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def evaluate(name, model, X_test, y_test, attack_types_test=None):
    y_pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:, 1]
    else:
        y_score = y_pred.astype(float)

    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    try:
        roc = roc_auc_score(y_test, y_score)
    except ValueError:
        roc = float("nan")

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    report = classification_report(y_test, y_pred, digits=4, zero_division=0)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0

    per_attack = {}
    if attack_types_test is not None:
        for atype in sorted(set(attack_types_test)):
            if atype in ("NONE", "", "nan"):
                continue
            mask = np.array([a == atype for a in attack_types_test])
            if mask.sum() == 0:
                continue
            # Recall among windows that belong to this attack type
            per_attack[atype] = float((y_pred[mask] == 1).mean())

    return {
        "name": name,
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "auc": float(roc) if roc == roc else None,
        "accuracy": float((y_pred == y_test).mean()),
        "fpr": fpr,
        "cm": cm.tolist(),
        "report": report,
        "per_attack_recall": per_attack,
        "y_pred": y_pred,
        "y_score": y_score,
    }


def print_result(r):
    print(f"\n=== {r['name']} ===")
    print(f"  Precision={r['precision']:.4f}  Recall={r['recall']:.4f}  "
          f"F1={r['f1']:.4f}  FPR={r['fpr']:.4f}  AUC={r['auc']}  Acc={r['accuracy']:.4f}")
    print(f"  Confusion matrix: {r['cm']}")
    if r["per_attack_recall"]:
        print(f"  Per-attack recall: {r['per_attack_recall']}")
    print(r["report"])


def _fit_eval_subset(name, feature_names, df, y):
    X = df[feature_names].to_numpy(dtype=float)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    clf = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf.fit(X_tr, y_tr)
    return evaluate(name, clf, X_te, y_te)


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

def plot_confusion(cm, title, path):
    disp = ConfusionMatrixDisplay(
        confusion_matrix=np.array(cm), display_labels=["Normal", "Attack"]
    )
    fig, ax = plt.subplots(figsize=(5, 4), dpi=150)
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved {path}")


def plot_roc(y_test, y_score, title, path):
    fpr, tpr, _ = roc_curve(y_test, y_score)
    roc_auc = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(5, 4), dpi=150)
    ax.plot(fpr, tpr, lw=2, label=f"AUC = {roc_auc:.3f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(title)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved {path}")


def plot_model_comparison(results, path):
    names = [r["name"] for r in results]
    f1s = [r["f1"] for r in results]
    recalls = [r["recall"] for r in results]
    aucs = [r["auc"] if r["auc"] is not None else 0.0 for r in results]
    x = np.arange(len(names))
    w = 0.25
    fig, ax = plt.subplots(figsize=(8, 4), dpi=150)
    ax.bar(x - w, f1s, w, label="F1")
    ax.bar(x, recalls, w, label="Recall")
    ax.bar(x + w, aucs, w, label="AUC")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison (primary metrics)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved {path}")


def plot_ablation(full_f1, nids_f1, path):
    fig, ax = plt.subplots(figsize=(5, 4), dpi=150)
    bars = ax.bar(["Full (NIDS+HIDS)", "NIDS-only"], [full_f1, nids_f1],
                  color=["#1f77b4", "#ff7f0e"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1")
    ax.set_title("Fusion Ablation: value of HIDS features")
    for b, v in zip(bars, [full_f1, nids_f1]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}",
                ha="center", fontsize=10)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved {path}")


def plot_telemetry(df, path_prefix):
    """Optional time-series plots when window_start is available."""
    if "window_start" not in df.columns:
        return
    import pandas as pd

    t = pd.to_datetime(df["window_start"], errors="coerce")
    if t.isna().all():
        return
    t0 = t.min()
    secs = (t - t0).dt.total_seconds().to_numpy()
    labels = df[LABEL_COL].to_numpy()

    def shade(ax):
        in_attack = False
        start = None
        for i, lab in enumerate(labels):
            if lab == 1 and not in_attack:
                in_attack = True
                start = secs[i]
            elif lab == 0 and in_attack:
                ax.axvspan(start, secs[i], color="#d62728", alpha=0.15)
                in_attack = False
        if in_attack:
            ax.axvspan(start, secs[-1], color="#d62728", alpha=0.15)

    fig, ax = plt.subplots(figsize=(10, 4), dpi=150)
    ax.plot(secs, df["heap"] / 1024.0, label="Heap (KB)", lw=1.5)
    ax.plot(secs, df["minheap"] / 1024.0, label="Min heap (KB)", ls="--", lw=1)
    shade(ax)
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel("Heap (KB)")
    ax.set_title("Heap under attack windows (red = labeled attack)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    p = f"{path_prefix}_heap.png"
    fig.savefig(p)
    plt.close(fig)
    print(f"Saved {p}")

    fig, ax = plt.subplots(figsize=(10, 4), dpi=150)
    ax.plot(secs, df["packet_density"], label="Packet density λ", color="#2ca02c")
    ax.plot(secs, df["deauth_packets"], label="Deauth count", color="#d62728", alpha=0.7)
    shade(ax)
    ax.set_xlabel("Elapsed time (s)")
    ax.set_title("Windowed network features")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    p = f"{path_prefix}_density.png"
    fig.savefig(p)
    plt.close(fig)
    print(f"Saved {p}")


# ---------------------------------------------------------------------------
# m2cgen export -> model.h matching firmware API
# ---------------------------------------------------------------------------

def export_model_h(clf, feature_names, out_path):
    """Export a sklearn DecisionTree to C via m2cgen, wrapped for the firmware."""
    raw = m2c.export_to_c(clf)
    # m2cgen emits `double score[N]` and fills it; we wrap to our struct API.

    # Extract the body of the generated score function.
    # Typical form:
    #   void score(double * input, double * output) { ... }
    m = re.search(
        r"void\s+score\s*\(\s*double\s*\*\s*input\s*,\s*double\s*\*\s*output\s*\)\s*\{(.*)\}",
        raw,
        re.DOTALL,
    )
    if not m:
        # Fallback: keep the whole generated code and add a thin wrapper that
        # packs the struct into a double array.
        body = None
        score_fn = raw
    else:
        body = m.group(1)
        score_fn = None

    fields = "\n".join(f"    double {name};" for name in feature_names)
    pack_lines = "\n".join(
        f"    input[{i}] = f->{name};" for i, name in enumerate(feature_names)
    )

    if body is not None:
        # Inline the m2cgen body after packing the feature vector.
        predict_fn = f"""
static inline int nids_predict(const nids_window_features_t *f)
{{
    double input[{len(feature_names)}];
    double output[2];
{pack_lines}
    /* --- m2cgen-generated tree --- */
{body}
    /* class 1 = attack */
    return (output[1] > output[0]) ? 1 : 0;
}}
"""
        generated_blob = ""
    else:
        predict_fn = f"""
static inline int nids_predict(const nids_window_features_t *f)
{{
    double input[{len(feature_names)}];
    double output[2];
{pack_lines}
    score(input, output);
    return (output[1] > output[0]) ? 1 : 0;
}}
"""
        generated_blob = score_fn + "\n"

    header = f"""/**
 * model.h - Auto-generated zero-dependency decision tree for ESP32 edge NIDS.
 *
 * Generated by analyze_and_train.py via m2cgen.
 * Feature order MUST match nids_features.WINDOW_FEATURES / firmware fill order.
 * DO NOT edit by hand — regenerate with: python analyze_and_train.py
 *
 * Generated: {datetime.now().isoformat(timespec='seconds')}
 */
#ifndef NIDS_MODEL_H
#define NIDS_MODEL_H

#include <string.h>  /* memcpy used by m2cgen tree */

#ifdef __cplusplus
extern "C" {{
#endif

typedef struct {{
{fields}
}} nids_window_features_t;

{generated_blob}{predict_fn}

#ifdef __cplusplus
}}
#endif

#endif /* NIDS_MODEL_H */
"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(header)
    print(f"Exported m2cgen model -> {out_path}")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def build_models():
    models = {
        "DecisionTree": DecisionTreeClassifier(
            max_depth=4, class_weight="balanced", random_state=42
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=80, max_depth=6, class_weight="balanced",
            random_state=42, n_jobs=-1,
        ),
    }
    for name, factory in OPTIONAL_MODELS.items():
        models[name] = factory()
    return models


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None, help="nids_windows_*.csv path")
    ap.add_argument("--export-model", default="DecisionTree",
                    help="Which model to export to model.h (must be a tree)")
    ap.add_argument("--no-plots", action="store_true")
    ap.add_argument("--strict-export", action="store_true",
                    help="Refuse to write model.h if heap dominates feature importance")
    args = ap.parse_args()

    dataset = args.dataset or find_default_dataset()
    print(f"Loading window dataset: {dataset}")
    df = load_windows(dataset)
    n_pos = int(df[LABEL_COL].sum())
    n_neg = len(df) - n_pos
    print(f"  windows={len(df)}  normal={n_neg}  attack={n_pos}")
    print(f"  attack types: {Counter(df[ATTACK_TYPE_COL])}")
    if n_neg == 0 or n_pos == 0:
        raise SystemExit("Need both classes present. Re-collect a balanced dataset.")

    X = df[WINDOW_FEATURES].to_numpy(dtype=float)
    y = df[LABEL_COL].to_numpy(dtype=int)
    attack_types = df[ATTACK_TYPE_COL].astype(str).to_numpy()

    X_train, X_test, y_train, y_test, at_train, at_test = train_test_split(
        X, y, attack_types, test_size=0.3, random_state=42, stratify=y
    )
    print(f"  train={len(y_train)}  test={len(y_test)}  "
          f"(class_weight=balanced where supported)")

    # --- Multi-model comparison ---
    models = build_models()
    results = []
    fitted = {}
    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)
        fitted[name] = model
        r = evaluate(name, model, X_test, y_test, at_test)
        print_result(r)
        results.append(r)

    # Pick best by F1 for reporting (export stays a shallow DecisionTree for MCU)
    best = max(results, key=lambda r: r["f1"])
    print(f"\nBest by F1: {best['name']} (F1={best['f1']:.4f})")

    # --- Ablations: ±HIDS, ±P0 WIDS ---
    print("\n--- Ablation (HIDS + P0 WIDS) ---")
    dt_full = next(r for r in results if r["name"] == "DecisionTree")
    abl_nids = _fit_eval_subset("DT NIDS-only (no HIDS)", NIDS_ONLY_FEATURES, df, y)
    print_result(abl_nids)
    # Baseline wireless (no P0 WIDS) + HIDS
    baseline_feats = NIDS_BASELINE_FEATURES + HIDS_FEATURES
    abl_no_wids = _fit_eval_subset("DT baseline (no P0 WIDS)", baseline_feats, df, y)
    print_result(abl_no_wids)
    # Wireless baseline only (no HIDS, no P0)
    abl_base_only = _fit_eval_subset("DT wireless-baseline only", NIDS_BASELINE_FEATURES, df, y)
    print_result(abl_base_only)

    delta_hids = dt_full["f1"] - abl_nids["f1"]
    delta_wids = dt_full["f1"] - abl_no_wids["f1"]
    print(f"\nFusion lift (full - NIDS-only) F1 = {delta_hids:+.4f}  HIDS={HIDS_FEATURES}")
    print(f"WIDS P0 lift (full - no P0) F1 = {delta_wids:+.4f}  P0={WIDS_P0_FEATURES}")
    print("  Note: P0 lift stays ~0 until you re-collect with firmware that emits "
          "deauth_tgt/seq_jump.")

    # --- Export deployable DecisionTree via m2cgen ---
    export_name = args.export_model
    if export_name not in fitted:
        raise SystemExit(f"--export-model {export_name} not among {list(fitted)}")
    export_clf = fitted[export_name]
    if not isinstance(export_clf, DecisionTreeClassifier):
        # For RF/boosters, distill a shallow DT for MCU deployment
        print(f"Distilling {export_name} -> shallow DecisionTree for MCU export...")
        soft = export_clf.predict(X_train)
        export_clf = DecisionTreeClassifier(
            max_depth=4, class_weight="balanced", random_state=42
        )
        export_clf.fit(X_train, soft)
        distill_r = evaluate("Distilled DT (export)", export_clf, X_test, y_test, at_test)
        print_result(distill_r)

    print("\n--- Exported Decision Tree rules ---")
    print(export_text(export_clf, feature_names=WINDOW_FEATURES))

    heap_imp = 0.0
    if hasattr(export_clf, "feature_importances_"):
        print("\nFeature importances (export tree):")
        for fname, imp in sorted(
            zip(WINDOW_FEATURES, export_clf.feature_importances_),
            key=lambda x: -x[1],
        ):
            if fname == "heap":
                heap_imp = float(imp)
            if imp > 0:
                print(f"  {fname:>16}: {imp:.4f}")

    if args.strict_export and heap_imp > MAX_HEAP_IMPORTANCE:
        raise SystemExit(
            f"--strict-export: heap importance {heap_imp:.3f} > {MAX_HEAP_IMPORTANCE}. "
            "Re-collect a balanced dataset (see note/lab_runbook.md) before flashing."
        )

    model_h = MODEL_H
    export_model_h(export_clf, WINDOW_FEATURES, model_h)

    # --- Plots + metrics JSON ---
    if not args.no_plots:
        plot_model_comparison(
            results, os.path.join(OUTPUT_DIR, "model_comparison.png")
        )
        plot_confusion(
            dt_full["cm"],
            "Decision Tree Confusion Matrix (window features)",
            os.path.join(OUTPUT_DIR, "confusion_matrix.png"),
        )
        plot_roc(
            y_test, dt_full["y_score"],
            "Decision Tree ROC (window features)",
            os.path.join(OUTPUT_DIR, "roc_curve.png"),
        )
        plot_ablation(
            dt_full["f1"], abl_nids["f1"],
            os.path.join(OUTPUT_DIR, "fusion_ablation.png"),
        )
        # Extended ablation bars
        fig, ax = plt.subplots(figsize=(7, 4), dpi=150)
        names = ["Full", "No HIDS", "No P0 WIDS", "Baseline RF"]
        vals = [dt_full["f1"], abl_nids["f1"], abl_no_wids["f1"], abl_base_only["f1"]]
        ax.bar(names, vals, color=["#1f77b4", "#ff7f0e", "#2ca02c", "#7f7f7f"])
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("F1")
        ax.set_title("Ablation: full vs -HIDS vs -P0 WIDS vs baseline")
        for i, v in enumerate(vals):
            ax.text(i, v + 0.02, f"{v:.3f}", ha="center", fontsize=9)
        fig.tight_layout()
        p = os.path.join(OUTPUT_DIR, "ablation_wids_hids.png")
        fig.savefig(p)
        plt.close(fig)
        print(f"Saved {p}")
        plot_telemetry(df, os.path.join(OUTPUT_DIR, "telemetry_window"))

        fig, ax = plt.subplots(figsize=(10, 5), dpi=200)
        plot_tree(
            export_clf, feature_names=WINDOW_FEATURES,
            class_names=["Normal", "Attack"], filled=True, rounded=True,
            fontsize=7, ax=ax,
        )
        ax.set_title("Exported Decision Tree (m2cgen / on-device)")
        fig.tight_layout()
        tree_path = os.path.join(OUTPUT_DIR, "decision_tree_structure.png")
        fig.savefig(tree_path)
        plt.close(fig)
        print(f"Saved {tree_path}")

    metrics = {
        "dataset": os.path.basename(dataset),
        "n_windows": len(df),
        "n_normal": n_neg,
        "n_attack": n_pos,
        "class_balance_note": (
            "Metrics use class_weight=balanced; prefer F1/Recall/AUC over accuracy "
            "when classes are imbalanced. Re-collect more NORMAL windows for paper."
        ),
        "models": [
            {k: v for k, v in r.items() if k not in ("y_pred", "y_score", "report")}
            for r in results
        ],
        "ablation": {
            "full_f1": dt_full["f1"],
            "nids_only_f1": abl_nids["f1"],
            "no_p0_wids_f1": abl_no_wids["f1"],
            "baseline_rf_only_f1": abl_base_only["f1"],
            "fusion_lift_f1": delta_hids,
            "wids_p0_lift_f1": delta_wids,
            "hids_features": HIDS_FEATURES,
            "nids_features": NIDS_ONLY_FEATURES,
            "wids_p0_features": WIDS_P0_FEATURES,
        },
        "decision_tree": {
            "fpr": dt_full["fpr"],
            "per_attack_recall": dt_full["per_attack_recall"],
            "heap_importance": heap_imp,
        },
        "exported_model": export_name,
        "feature_order": WINDOW_FEATURES,
    }
    metrics_path = os.path.join(OUTPUT_DIR, "eval_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nWrote metrics -> {metrics_path}")
    print("Done.")


if __name__ == "__main__":
    main()
