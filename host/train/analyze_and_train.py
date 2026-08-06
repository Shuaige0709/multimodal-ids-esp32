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
  python host/train/analyze_and_train.py --export-variant no-heap   # heap-neutralized MCU export

PCA (offline analysis for advisor / report; not deployed on ESP32):
  runs automatically with plots -> docs/figures/pca_*.png
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
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
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
    HIDS_NO_HEAP_FEATURES,
    LABEL_COL,
    MAX_HEAP_IMPORTANCE,
    NIDS_BASELINE_FEATURES,
    NIDS_ONLY_FEATURES,
    NO_HEAP_FEATURES,
    RSSI_VALID_MAX,
    RSSI_VALID_MIN,
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
    # Clean already-aggregated dirty RSSI for training (positive / out-of-range).
    # Typical bogus pattern: rssi_mean > 0 and snr_mean ≈ rssi_mean (noise_floor≈0).
    bad = (df["rssi_mean"] < RSSI_VALID_MIN) | (df["rssi_mean"] > RSSI_VALID_MAX)
    if bad.any():
        mirror = bad & (df["snr_mean"] - df["rssi_mean"]).abs().le(1e-6)
        n_bad = int(bad.sum())
        df.loc[bad, "rssi_mean"] = 0.0
        df.loc[bad, "rssi_var"] = 0.0
        df.loc[mirror, "snr_mean"] = 0.0
        print(f"  RF clean: zeroed rssi_mean on {n_bad} windows "
              f"(snr cleared on {int(mirror.sum())} mirror rows)")
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


def run_pca_analysis(X_train, X_all, y_all, attack_types, feature_names, out_dir, make_plots=True):
    """
    Standardize on train fold, fit PCA, report variance + PC1/PC2 loadings.
    Offline only — does not change the on-device DecisionTree export.
    """
    scaler = StandardScaler()
    Z_train = scaler.fit_transform(X_train)
    Z_all = scaler.transform(X_all)
    n_comp = min(10, Z_train.shape[1], Z_train.shape[0])
    pca = PCA(n_components=n_comp, random_state=42)
    pca.fit(Z_train)
    Z = pca.transform(Z_all)

    evr = pca.explained_variance_ratio_
    cum = np.cumsum(evr)
    print("\n--- PCA (StandardScaler fit on train; offline analysis) ---")
    for i, (v, c) in enumerate(zip(evr, cum), start=1):
        print(f"  PC{i}: explained={v:.4f}  cumulative={c:.4f}")

    def top_loadings(pc_idx, k=6):
        loads = pca.components_[pc_idx]
        order = np.argsort(-np.abs(loads))
        return [
            {"feature": feature_names[j], "loading": float(loads[j])}
            for j in order[:k]
        ]

    pc1_top = top_loadings(0)
    pc2_top = top_loadings(1) if n_comp > 1 else []
    print("  PC1 top |loading|:")
    for item in pc1_top:
        print(f"    {item['feature']:>16}: {item['loading']:+.4f}")
    if pc2_top:
        print("  PC2 top |loading|:")
        for item in pc2_top:
            print(f"    {item['feature']:>16}: {item['loading']:+.4f}")

    heap_idx = feature_names.index("heap") if "heap" in feature_names else None
    heap_on_pc1 = float(pca.components_[0][heap_idx]) if heap_idx is not None else None
    if heap_on_pc1 is not None:
        print(f"  heap loading on PC1: {heap_on_pc1:+.4f}")

    if make_plots and n_comp >= 2:
        # Variance scree
        fig, ax = plt.subplots(figsize=(6, 3.5), dpi=150)
        xs = np.arange(1, len(evr) + 1)
        ax.bar(xs, evr, color="#1f77b4", label="per-PC")
        ax.plot(xs, cum, "o-", color="#d62728", label="cumulative")
        ax.set_xlabel("Principal component")
        ax.set_ylabel("Explained variance ratio")
        ax.set_title("PCA explained variance (scaled window features)")
        ax.set_xticks(xs)
        ax.legend()
        fig.tight_layout()
        p_var = os.path.join(out_dir, "pca_variance.png")
        fig.savefig(p_var)
        plt.close(fig)
        print(f"Saved {p_var}")

        # Scatter by binary label
        fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
        for lab, name, color in ((0, "Normal", "#1f77b4"), (1, "Attack", "#d62728")):
            m = y_all == lab
            ax.scatter(
                Z[m, 0], Z[m, 1], s=8, alpha=0.35, c=color, label=name, edgecolors="none"
            )
        ax.set_xlabel(f"PC1 ({evr[0]*100:.1f}%)")
        ax.set_ylabel(f"PC2 ({evr[1]*100:.1f}%)")
        ax.set_title("PCA projection (label)")
        ax.legend(markerscale=2)
        fig.tight_layout()
        p_lab = os.path.join(out_dir, "pca_scatter_label.png")
        fig.savefig(p_lab)
        plt.close(fig)
        print(f"Saved {p_lab}")

        # Scatter by attack_type
        fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
        types = sorted(set(attack_types))
        cmap = plt.get_cmap("tab10")
        for i, at in enumerate(types):
            m = attack_types == at
            ax.scatter(
                Z[m, 0], Z[m, 1], s=8, alpha=0.35,
                c=[cmap(i % 10)], label=at, edgecolors="none",
            )
        ax.set_xlabel(f"PC1 ({evr[0]*100:.1f}%)")
        ax.set_ylabel(f"PC2 ({evr[1]*100:.1f}%)")
        ax.set_title("PCA projection (attack_type)")
        ax.legend(markerscale=2, fontsize=8)
        fig.tight_layout()
        p_at = os.path.join(out_dir, "pca_scatter_attack.png")
        fig.savefig(p_at)
        plt.close(fig)
        print(f"Saved {p_at}")

        # PC1 loadings bar
        fig, ax = plt.subplots(figsize=(7, 3.5), dpi=150)
        loads = pca.components_[0]
        order = np.argsort(np.abs(loads))[::-1]
        names = [feature_names[j] for j in order]
        vals = loads[order]
        colors = ["#d62728" if n == "heap" else "#1f77b4" for n in names]
        ax.barh(names[::-1], vals[::-1], color=colors[::-1])
        ax.set_xlabel("PC1 loading (after standardization)")
        ax.set_title("PC1 feature loadings (heap highlighted)")
        fig.tight_layout()
        p_ld = os.path.join(out_dir, "pca_pc1_loadings.png")
        fig.savefig(p_ld)
        plt.close(fig)
        print(f"Saved {p_ld}")

    return {
        "n_components": int(n_comp),
        "explained_variance_ratio": [float(x) for x in evr],
        "cumulative_variance": [float(x) for x in cum],
        "pc1_top_loadings": pc1_top,
        "pc2_top_loadings": pc2_top,
        "heap_loading_pc1": heap_on_pc1,
        "note": (
            "PCA is offline analysis only (scaler+PCA fit on train). "
            "On-device model remains the exported DecisionTree on raw window features."
        ),
    }


def run_lda_analysis(X_train, y_train, X_all, y_all, attack_types, feature_names, out_dir, make_plots=True):
    """
    LDA for supervised projection (binary label + optional multiclass attack_type).
    Offline only — not exported to the MCU.
    """
    scaler = StandardScaler()
    Z_train = scaler.fit_transform(X_train)
    Z_all = scaler.transform(X_all)

    print("\n--- LDA (supervised; scaler fit on train) ---")
    lda_bin = LinearDiscriminantAnalysis(n_components=1)
    lda_bin.fit(Z_train, y_train)
    ld1 = lda_bin.transform(Z_all)[:, 0]
    # coef_ shape (1, n_features) for binary
    coef = lda_bin.coef_.ravel()
    order = np.argsort(-np.abs(coef))
    top = [
        {"feature": feature_names[j], "coef": float(coef[j])}
        for j in order[:8]
    ]
    print("  Binary LDA (Normal vs Attack) - top |coef|:")
    for item in top:
        print(f"    {item['feature']:>16}: {item['coef']:+.4f}")
    heap_coef = None
    if "heap" in feature_names:
        heap_coef = float(coef[feature_names.index("heap")])
        print(f"  heap LDA coef: {heap_coef:+.4f}")

    # Hold-out style score on all data is optimistic; report train accuracy only as sanity
    train_acc = float(lda_bin.score(Z_train, y_train))
    print(f"  LDA train accuracy (sanity): {train_acc:.4f}")

    multi_info = None
    types = sorted(set(attack_types))
    if len(types) >= 3:
        # Map attack_type to ints; need enough samples per class
        type_to_i = {t: i for i, t in enumerate(types)}
        y_multi = np.array([type_to_i[t] for t in attack_types])
        # Fit multiclass LDA on full standardized X with same scaler (train indices via y_train length mismatch)
        # Use train mask: rebuild from stratified split indices by matching rows — simpler: fit on all for viz only
        n_comp_m = min(2, len(types) - 1)
        lda_m = LinearDiscriminantAnalysis(n_components=n_comp_m)
        Zm = scaler.transform(X_all)
        try:
            lda_m.fit(Zm, y_multi)
            emb = lda_m.transform(Zm)
            multi_info = {
                "classes": types,
                "n_components": int(n_comp_m),
                "explained_variance_ratio": [
                    float(x) for x in getattr(lda_m, "explained_variance_ratio_", [])
                ],
            }
            print(f"  Multiclass LDA on attack_type: classes={types}, n_comp={n_comp_m}")
        except Exception as exc:
            print(f"  Multiclass LDA skipped: {exc}")
            emb = None
            lda_m = None
    else:
        emb = None
        lda_m = None

    if make_plots:
        fig, ax = plt.subplots(figsize=(7, 3.5), dpi=150)
        ax.hist(ld1[y_all == 0], bins=40, alpha=0.55, label="Normal", color="#1f77b4", density=True)
        ax.hist(ld1[y_all == 1], bins=40, alpha=0.55, label="Attack", color="#d62728", density=True)
        ax.set_xlabel("LD1")
        ax.set_ylabel("Density")
        ax.set_title("LDA projection (binary label)")
        ax.legend()
        fig.tight_layout()
        p = os.path.join(out_dir, "lda_ld1_hist.png")
        fig.savefig(p)
        plt.close(fig)
        print(f"Saved {p}")

        fig, ax = plt.subplots(figsize=(7, 3.5), dpi=150)
        names = [feature_names[j] for j in order[:12]]
        vals = coef[order[:12]]
        colors = ["#d62728" if n == "heap" else "#1f77b4" for n in names]
        ax.barh(names[::-1], vals[::-1], color=colors[::-1])
        ax.set_xlabel("LDA coefficient (scaled features)")
        ax.set_title("Binary LDA coefficients (heap highlighted)")
        fig.tight_layout()
        p = os.path.join(out_dir, "lda_coefficients.png")
        fig.savefig(p)
        plt.close(fig)
        print(f"Saved {p}")

        if emb is not None and emb.shape[1] >= 2:
            fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
            cmap = plt.get_cmap("tab10")
            for i, at in enumerate(types):
                m = attack_types == at
                ax.scatter(
                    emb[m, 0], emb[m, 1], s=8, alpha=0.35,
                    c=[cmap(i % 10)], label=at, edgecolors="none",
                )
            ax.set_xlabel("LD1")
            ax.set_ylabel("LD2")
            ax.set_title("LDA projection (attack_type)")
            ax.legend(markerscale=2, fontsize=8)
            fig.tight_layout()
            p = os.path.join(out_dir, "lda_scatter_attack.png")
            fig.savefig(p)
            plt.close(fig)
            print(f"Saved {p}")

    return {
        "binary_top_coefficients": top,
        "heap_coefficient": heap_coef,
        "train_accuracy": train_acc,
        "multiclass": multi_info,
        "note": (
            "LDA is offline supervised projection. "
            "On-device model remains the exported DecisionTree."
        ),
    }


def run_hyperparameter_report(X_train, y_train, X_test, y_test, out_dir, make_plots=True):
    """Grid-search shallow DecisionTree hyperparameters; report only (export stays default unless noted)."""
    print("\n--- Hyperparameter grid (DecisionTree, F1, CV=3 on train) ---")
    param_grid = {
        "max_depth": [2, 3, 4, 5, 6, 8],
        "min_samples_leaf": [1, 5, 10, 20],
        "class_weight": ["balanced"],
    }
    base = DecisionTreeClassifier(random_state=42)
    gs = GridSearchCV(
        base,
        param_grid,
        scoring="f1",
        cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=42),
        n_jobs=-1,
        refit=True,
    )
    gs.fit(X_train, y_train)
    best = gs.best_params_
    cv_f1 = float(gs.best_score_)
    test_f1 = float(f1_score(y_test, gs.predict(X_test)))
    # Default export depth for comparison
    default = DecisionTreeClassifier(
        max_depth=4, class_weight="balanced", random_state=42
    )
    default.fit(X_train, y_train)
    default_test_f1 = float(f1_score(y_test, default.predict(X_test)))

    print(f"  Best params: {best}")
    print(f"  Best CV F1: {cv_f1:.4f}")
    print(f"  Best model test F1: {test_f1:.4f}")
    print(f"  Default (max_depth=4) test F1: {default_test_f1:.4f}")
    print("  Note: model.h export still uses max_depth=4 unless you change build_models().")

    # Pivot-like rows for JSON
    rows = []
    for params, mean_s, std_s in zip(
        gs.cv_results_["params"],
        gs.cv_results_["mean_test_score"],
        gs.cv_results_["std_test_score"],
    ):
        rows.append({
            "max_depth": params["max_depth"],
            "min_samples_leaf": params["min_samples_leaf"],
            "mean_cv_f1": float(mean_s),
            "std_cv_f1": float(std_s),
        })
    rows.sort(key=lambda r: -r["mean_cv_f1"])

    if make_plots:
        # Heatmap depth x leaf
        depths = sorted(param_grid["max_depth"])
        leaves = sorted(param_grid["min_samples_leaf"])
        mat = np.full((len(leaves), len(depths)), np.nan)
        for r in rows:
            i = leaves.index(r["min_samples_leaf"])
            j = depths.index(r["max_depth"])
            mat[i, j] = r["mean_cv_f1"]
        fig, ax = plt.subplots(figsize=(6, 3.5), dpi=150)
        im = ax.imshow(mat, aspect="auto", cmap="viridis", vmin=0, vmax=1)
        ax.set_xticks(range(len(depths)))
        ax.set_xticklabels(depths)
        ax.set_yticks(range(len(leaves)))
        ax.set_yticklabels(leaves)
        ax.set_xlabel("max_depth")
        ax.set_ylabel("min_samples_leaf")
        ax.set_title("DecisionTree CV F1 heatmap")
        for i in range(len(leaves)):
            for j in range(len(depths)):
                if mat[i, j] == mat[i, j]:
                    ax.text(j, i, f"{mat[i, j]:.2f}", ha="center", va="center", color="w", fontsize=8)
        fig.colorbar(im, ax=ax, fraction=0.046)
        fig.tight_layout()
        p = os.path.join(out_dir, "hyperparam_dt_heatmap.png")
        fig.savefig(p)
        plt.close(fig)
        print(f"Saved {p}")

    return {
        "best_params": best,
        "best_cv_f1": cv_f1,
        "best_test_f1": test_f1,
        "default_max_depth4_test_f1": default_test_f1,
        "top_configs": rows[:10],
        "export_policy": "MCU export keeps max_depth=4 (shallow); grid is for report only.",
    }


def write_dataset_content_report(df, dataset_path, out_dir):
    """Human-readable + JSON summary of what's in the window CSV."""
    print("\n--- Dataset content report ---")
    n = len(df)
    n_pos = int(df[LABEL_COL].sum())
    n_neg = n - n_pos
    atk_counts = Counter(df[ATTACK_TYPE_COL].astype(str))
    tcol = "window_start" if "window_start" in df.columns else None
    t_min = t_max = None
    if tcol:
        import pandas as pd

        ts = pd.to_datetime(df[tcol], errors="coerce")
        t_min = str(ts.min())
        t_max = str(ts.max())

    feat_stats = {}
    for c in WINDOW_FEATURES:
        s = df[c]
        feat_stats[c] = {
            "mean": float(s.mean()),
            "std": float(s.std()),
            "min": float(s.min()),
            "p50": float(s.median()),
            "max": float(s.max()),
            "frac_zero": float((s == 0).mean()),
        }

    dens_nuniq = int(df["packet_density"].nunique()) if "packet_density" in df.columns else None
    pkts_mode = int(df["total_packets"].mode().iloc[0]) if "total_packets" in df.columns else None
    warnings_list = []
    if dens_nuniq is not None and dens_nuniq <= 4:
        warnings_list.append(
            "packet_density nearly constant (syslog thinning) - see density contract note"
        )
    if feat_stats.get("minheap", {}).get("std", 1) < 1e-6:
        warnings_list.append("minheap has ~zero variance in this capture")

    report = {
        "dataset": os.path.basename(dataset_path),
        "n_windows": n,
        "n_normal": n_neg,
        "n_attack": n_pos,
        "attack_fraction": float(n_pos / n) if n else 0.0,
        "attack_type_counts": dict(atk_counts),
        "time_range": {"start": t_min, "end": t_max},
        "feature_stats": feat_stats,
        "packet_density_nunique": dens_nuniq,
        "total_packets_mode": pkts_mode,
        "warnings": warnings_list,
        "feature_order": WINDOW_FEATURES,
    }

    json_path = os.path.join(out_dir, "dataset_report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"Wrote {json_path}")

    md_path = os.path.join(out_dir, "dataset_report.md")
    lines = [
        f"# Dataset content report",
        "",
        f"- **File:** `{report['dataset']}`",
        f"- **Windows:** {n} (NORMAL {n_neg} / ATTACK {n_pos}, attack frac={report['attack_fraction']:.3f})",
        f"- **Time range:** {t_min} → {t_max}",
        "",
        "## Attack types",
        "",
        "| Type | Count |",
        "|------|------:|",
    ]
    for k, v in sorted(atk_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {k} | {v} |")
    lines += [
        "",
        "## Feature snapshot (median / std)",
        "",
        "| Feature | median | std | frac zero |",
        "|---------|-------:|----:|----------:|",
    ]
    for c in WINDOW_FEATURES:
        st = feat_stats[c]
        lines.append(
            f"| `{c}` | {st['p50']:.4g} | {st['std']:.4g} | {st['frac_zero']:.3f} |"
        )
    if warnings_list:
        lines += ["", "## Warnings", ""]
        for w in warnings_list:
            lines.append(f"- {w}")
    lines += [
        "",
        "## Notes",
        "",
        "- Generated by `analyze_and_train.py` (after RF clean on load).",
        "- Pair with PCA / LDA / hyperparam figures in this folder.",
        "",
    ]
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"Wrote {md_path}")
    for w in warnings_list:
        print(f"  WARN: {w}")
    return report


def plot_heap_ablation(rows, path):
    """rows: list of (label, f1, fpr)."""
    labels = [r[0] for r in rows]
    f1s = [r[1] for r in rows]
    fprs = [r[2] for r in rows]
    x = np.arange(len(labels))
    w = 0.35
    fig, ax = plt.subplots(figsize=(8, 4), dpi=150)
    ax.bar(x - w / 2, f1s, w, label="F1", color="#1f77b4")
    ax.bar(x + w / 2, fprs, w, label="FPR", color="#d62728")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Heap dependence: full vs no-heap variants")
    ax.legend()
    for i, (f1, fpr) in enumerate(zip(f1s, fprs)):
        ax.text(i - w / 2, f1 + 0.02, f"{f1:.2f}", ha="center", fontsize=8)
        ax.text(i + w / 2, fpr + 0.02, f"{fpr:.2f}", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved {path}")


def _heap_importance(clf, feature_names):
    if not hasattr(clf, "feature_importances_"):
        return 0.0
    for name, imp in zip(feature_names, clf.feature_importances_):
        if name == "heap":
            return float(imp)
    return 0.0


def _fit_exportable_no_heap(df, y, attack_types):
    """
    Train a DT on full WINDOW_FEATURES but with heap neutralized (constant),
    so model.h field order stays firmware-compatible and heap cannot dominate.
    """
    X = df[WINDOW_FEATURES].to_numpy(dtype=float)
    X_tr, X_te, y_tr, y_te, at_tr, at_te = train_test_split(
        X, y, attack_types, test_size=0.3, random_state=42, stratify=y
    )
    heap_idx = WINDOW_FEATURES.index("heap")
    # Use NORMAL rows in train only
    normal_heap = X_tr[y_tr == 0, heap_idx]
    fill = float(np.median(normal_heap)) if len(normal_heap) else 0.0
    X_tr = X_tr.copy()
    X_te = X_te.copy()
    X_tr[:, heap_idx] = fill
    X_te[:, heap_idx] = fill
    clf = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf.fit(X_tr, y_tr)
    r = evaluate("DT exportable (heap neutralized)", clf, X_te, y_te, at_te)
    r["heap_fill_value"] = fill
    r["heap_importance"] = _heap_importance(clf, WINDOW_FEATURES)
    return clf, r


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
    ap.add_argument(
        "--export-variant",
        choices=("full", "no-heap"),
        default="full",
        help="full=default multimodal DT; no-heap=heap-neutralized DT (same model.h layout)",
    )
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

    # --- Offline advisor reports: dataset / PCA / LDA / hyperparameters ---
    dataset_info = write_dataset_content_report(df, dataset, OUTPUT_DIR)
    pca_info = run_pca_analysis(
        X_train, X, y, attack_types, WINDOW_FEATURES, OUTPUT_DIR,
        make_plots=not args.no_plots,
    )
    lda_info = run_lda_analysis(
        X_train, y_train, X, y, attack_types, WINDOW_FEATURES, OUTPUT_DIR,
        make_plots=not args.no_plots,
    )
    hyper_info = run_hyperparameter_report(
        X_train, y_train, X_test, y_test, OUTPUT_DIR,
        make_plots=not args.no_plots,
    )

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
    if abs(delta_wids) < 1e-6:
        print("  Note: P0 lift~0 - tree prefers other splits (often heap); fields may still be nonzero.")

    # --- Heap dependence ablations ---
    print("\n--- Ablation (heap dependence) ---")
    abl_no_heap = _fit_eval_subset("DT no-heap (drop heap col)", NO_HEAP_FEATURES, df, y)
    print_result(abl_no_heap)
    multimodal_no_heap = list(NIDS_ONLY_FEATURES) + list(HIDS_NO_HEAP_FEATURES)
    abl_hids_wo_heap = _fit_eval_subset(
        "DT HIDS-sans-heap + wireless", multimodal_no_heap, df, y
    )
    print_result(abl_hids_wo_heap)
    noheap_clf, abl_export_nh = _fit_exportable_no_heap(df, y, attack_types)
    print_result(abl_export_nh)
    print(
        f"  heap fill (NORMAL train median)={abl_export_nh['heap_fill_value']:.1f}  "
        f"heap_importance={abl_export_nh['heap_importance']:.4f}"
    )
    print(
        f"\nHeap drop cost (full - no-heap col) F1 = "
        f"{dt_full['f1'] - abl_no_heap['f1']:+.4f}  "
        f"FPR {dt_full['fpr']:.3f} -> {abl_no_heap['fpr']:.3f}"
    )

    # Forced wireless importances (NIDS-only tree; RF cleaned at load)
    print("\n--- Forced wireless importances (NIDS-only tree, RF cleaned) ---")
    abl_wonly = abl_nids
    rf_imp = {}
    Xw = df[NIDS_ONLY_FEATURES].to_numpy(dtype=float)
    Xw_tr, _, yw_tr, _ = train_test_split(
        Xw, y, test_size=0.3, random_state=42, stratify=y
    )
    clf_w = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    clf_w.fit(Xw_tr, yw_tr)
    for fname, imp in sorted(
        zip(NIDS_ONLY_FEATURES, clf_w.feature_importances_), key=lambda x: -x[1]
    ):
        if imp > 0:
            rf_imp[fname] = float(imp)
            print(f"  {fname:>16}: {imp:.4f}")
    print(
        f"  (NIDS-only F1={abl_wonly['f1']:.4f} FPR={abl_wonly['fpr']:.4f} - same ablation as above)"
    )

    # --- Export deployable DecisionTree via m2cgen ---
    export_name = args.export_model
    if args.export_variant == "no-heap":
        export_clf = noheap_clf
        export_name = f"{export_name}+no-heap"
        print("\nExport variant: no-heap (heap neutralized, firmware feature order unchanged)")
    else:
        if export_name not in fitted:
            raise SystemExit(f"--export-model {export_name} not among {list(fitted)}")
        export_clf = fitted[export_name]
        if not isinstance(export_clf, DecisionTreeClassifier):
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

    heap_imp = _heap_importance(export_clf, WINDOW_FEATURES)
    if hasattr(export_clf, "feature_importances_"):
        print("\nFeature importances (export tree):")
        for fname, imp in sorted(
            zip(WINDOW_FEATURES, export_clf.feature_importances_),
            key=lambda x: -x[1],
        ):
            if imp > 0:
                print(f"  {fname:>16}: {imp:.4f}")

    if args.strict_export and heap_imp > MAX_HEAP_IMPORTANCE:
        raise SystemExit(
            f"--strict-export: heap importance {heap_imp:.3f} > {MAX_HEAP_IMPORTANCE}. "
            "Try --export-variant no-heap, or re-collect / retune before flashing."
        )

    export_model_h(export_clf, WINDOW_FEATURES, MODEL_H)

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

        plot_heap_ablation(
            [
                ("Full", dt_full["f1"], dt_full["fpr"]),
                ("No-heap col", abl_no_heap["f1"], abl_no_heap["fpr"]),
                ("HIDS\\heap+W", abl_hids_wo_heap["f1"], abl_hids_wo_heap["fpr"]),
                ("Export no-heap", abl_export_nh["f1"], abl_export_nh["fpr"]),
                ("NIDS-only", abl_nids["f1"], abl_nids["fpr"]),
            ],
            os.path.join(OUTPUT_DIR, "ablation_heap.png"),
        )

        plot_telemetry(df, os.path.join(OUTPUT_DIR, "telemetry_window"))

        fig, ax = plt.subplots(figsize=(10, 5), dpi=200)
        plot_tree(
            export_clf, feature_names=WINDOW_FEATURES,
            class_names=["Normal", "Attack"], filled=True, rounded=True,
            fontsize=7, ax=ax,
        )
        ax.set_title(f"Exported Decision Tree ({export_name})")
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
            "no_heap_f1": abl_no_heap["f1"],
            "no_heap_fpr": abl_no_heap["fpr"],
            "hids_sans_heap_f1": abl_hids_wo_heap["f1"],
            "hids_sans_heap_fpr": abl_hids_wo_heap["fpr"],
            "exportable_no_heap_f1": abl_export_nh["f1"],
            "exportable_no_heap_fpr": abl_export_nh["fpr"],
            "exportable_no_heap_heap_importance": abl_export_nh["heap_importance"],
            "heap_drop_f1_cost": dt_full["f1"] - abl_no_heap["f1"],
            "no_heap_features": NO_HEAP_FEATURES,
            "hids_no_heap_features": HIDS_NO_HEAP_FEATURES,
            "forced_wireless_f1": abl_wonly["f1"],
            "forced_wireless_fpr": abl_wonly["fpr"],
            "forced_wireless_importances": rf_imp,
        },
        "decision_tree": {
            "fpr": dt_full["fpr"],
            "per_attack_recall": dt_full["per_attack_recall"],
            "heap_importance": heap_imp,
        },
        "exported_model": export_name,
        "export_variant": args.export_variant,
        "feature_order": WINDOW_FEATURES,
        "dataset_report": {
            k: dataset_info[k]
            for k in (
                "dataset", "n_windows", "n_normal", "n_attack",
                "attack_fraction", "attack_type_counts", "time_range",
                "warnings", "packet_density_nunique", "total_packets_mode",
            )
            if k in dataset_info
        },
        "pca": pca_info,
        "lda": lda_info,
        "hyperparameters": hyper_info,
    }
    metrics_path = os.path.join(OUTPUT_DIR, "eval_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nWrote metrics -> {metrics_path}")
    print("Done.")


if __name__ == "__main__":
    main()
