"""Train/evaluate a PC-side model from raw_windows output, split by capture session.

python -m host.train.train_raw --dataset data/raw_windows_v1 --out models/raw_v1
No legacy model.h is overwritten. Unknown and quality-failed rows are excluded.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from host.train.raw_features import FEATURE_SETS, SCHEMA, WIRELESS, HARDWARE


def load_rows(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Feature schema mismatch; regenerate with raw_windows")
    digest = hashlib.sha256()
    rows = []
    seen = set()
    with (folder / "windows.jsonl").open("rb") as stream:
        for raw in stream:
            digest.update(raw)
            row = json.loads(raw)
            if row["schema"] != SCHEMA or row["window_ms"] != manifest["window_ms"]:
                raise ValueError("Mixed schema/window size")
            key = (row["session_id"], row["boot_id"], row["window_start_us"])
            if key in seen:
                raise ValueError("Duplicate window; refusing data leakage")
            seen.add(key)
            rows.append(row)
    if digest.hexdigest() != manifest["sha256"]:
        raise ValueError("Feature file checksum mismatch; regenerate rather than edit it")
    return rows, manifest


def train(dataset, output, *, feature_set="wireless", selected=None, test_sessions=None,
          seed=42, model_kind="tree"):
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.pipeline import make_pipeline
    from sklearn.tree import DecisionTreeClassifier

    rows, manifest = load_rows(dataset)
    if Path(output).exists():
        raise FileExistsError(f"Choose a NEW model directory: {output}")
    names = list(selected) if selected is not None else list(FEATURE_SETS[feature_set])
    if not names or len(set(names)) != len(names) or set(names)-set(WIRELESS+HARDWARE):
        raise ValueError("Features must be unique names from raw_features.py")
    kept = [r for r in rows if r["quality_ok"] and r["label"] is not None]
    if not kept:
        raise ValueError("No labeled, quality-valid windows. Collect normal/attack sessions first; unknown is not normal.")
    if any(r["label"] in ("0", "1") for r in kept):
        raise ValueError("Use explicit labels normal / attack-name, not ambiguous 0/1")
    groups = np.array([r["session_id"] for r in kept])
    y = np.array([int(r["label"] != "normal") for r in kept])
    if set(y) != {0, 1}:
        raise ValueError("Binary training requires both normal and attack labels")
    support = {str(c): len(set(groups[y == c])) for c in (0, 1)}
    if min(support.values()) < 2:
        raise ValueError("Each class needs at least TWO independent sessions (normal and attack each). "
                         "Do not split/copy one recording to pretend it is independent.")
    try:
        X = np.array([[np.nan if r["features"][n] is None else float(r["features"][n])
                       for n in names] for r in kept], dtype=float)
    except KeyError as exc:
        raise ValueError(f"Missing feature {exc}; regenerate features") from exc
    if np.isinf(X).any():
        raise ValueError("Infinite feature values")
    if test_sessions:
        unknown = set(test_sessions)-set(groups)
        if unknown:
            raise ValueError(f"Unknown/empty test sessions: {sorted(unknown)}")
        mask = np.isin(groups, test_sessions)
        tr, te = np.flatnonzero(~mask), np.flatnonzero(mask)
    else:
        tr = te = None
        # Choose by class coverage only, never by model score. Save exact split.
        for train_idx, test_idx in GroupShuffleSplit(n_splits=256, test_size=0.3, random_state=seed).split(X, y, groups):
            if set(y[train_idx]) == {0, 1} and set(y[test_idx]) == {0, 1}:
                tr, te = train_idx, test_idx
                break
        if tr is None:
            raise ValueError("Cannot make a session-disjoint split with both classes; collect more sessions or set --test-session")
    if set(y[tr]) != {0, 1} or set(y[te]) != {0, 1}:
        raise ValueError("Both train and test must contain normal and attack")
    if set(groups[tr]) & set(groups[te]):
        raise ValueError("Session leakage")
    entirely_missing = [names[i] for i in range(len(names)) if np.isnan(X[tr, i]).all()]
    if entirely_missing:
        raise ValueError(f"Features absent in every training window: {entirely_missing}. "
                         "Collect more data or explicitly select other --features.")
    estimator = (DecisionTreeClassifier(max_depth=5, min_samples_leaf=2,
                                       class_weight="balanced", random_state=seed)
                 if model_kind == "tree" else
                 RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=2,
                                        class_weight="balanced", random_state=seed, n_jobs=-1))
    pipeline = make_pipeline(SimpleImputer(strategy="median", add_indicator=True), estimator)
    pipeline.fit(X[tr], y[tr])  # imputation is fitted on TRAIN only
    pred = pipeline.predict(X[te])
    prob = pipeline.predict_proba(X[te])[:, list(pipeline.classes_).index(1)]
    report = {
        "schema": SCHEMA, "task": "binary normal=0, any named attack=1",
        "features": names, "window_ms": manifest["window_ms"], "seed": seed,
        "model": model_kind, "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__, "joblib_version": joblib.__version__,
        "feature_sha256": manifest["sha256"], "source_manifest": manifest,
        "rows_total": len(rows), "rows_used": len(kept),
        "excluded_unknown": sum(r["label"] is None for r in rows),
        "excluded_quality": sum(not r["quality_ok"] for r in rows),
        "labels": dict(Counter(r["label"] for r in kept)), "sessions_per_class": support,
        "train_sessions": sorted(set(groups[tr])), "test_sessions": sorted(set(groups[te])),
        "train_windows": len(tr), "test_windows": len(te),
        "missing_train_values": {name: int(np.isnan(X[tr, i]).sum()) for i, name in enumerate(names)},
        "missing_test_values": {name: int(np.isnan(X[te, i]).sum()) for i, name in enumerate(names)},
        "classification_report": classification_report(y[te], pred, labels=[0, 1],
                                 target_names=["normal", "attack"], output_dict=True, zero_division=0),
        "confusion_matrix_normal_attack": confusion_matrix(y[te], pred, labels=[0, 1]).tolist(),
        "roc_auc": float(roc_auc_score(y[te], prob)),
        "feature_importance": dict(zip(pipeline.steps[0][1].get_feature_names_out(names),
                                       map(float, estimator.feature_importances_))),
        "warnings": ["Held-out sessions are not proof of generalization to new environments.",
                     "Inspect loss/label guards and repeat experiments; capture cannot see all air traffic.",
                     "Hardware features may learn workload/uptime rather than attacks; compare wireless baseline.",
                     "This bundle is PC-only and is NOT an ESP32 model.h export."],
    }
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=False)
    bundle = {"schema": SCHEMA, "features": names, "window_ms": manifest["window_ms"],
              "pipeline": pipeline, "sklearn_version": sklearn.__version__,
              "train_sessions": report["train_sessions"], "test_sessions": report["test_sessions"]}
    joblib.dump(bundle, destination / "model.joblib")
    with (destination / "evaluation.json").open("x", encoding="utf-8") as out:
        json.dump(report, out, ensure_ascii=False, indent=2, allow_nan=False)
    with (destination / "test_predictions.jsonl").open("x", encoding="utf-8") as out:
        for index, prediction, probability in zip(te, pred, prob):
            r = kept[index]
            out.write(json.dumps({k: r[k] for k in ("session_id", "boot_id", "window_start_us", "label")}
                                | {"prediction": int(prediction), "attack_probability": float(probability)}) + "\n")
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", required=True, help="raw_windows output directory")
    p.add_argument("--out", required=True, help="NEW model directory")
    p.add_argument("--feature-set", choices=FEATURE_SETS, default="wireless")
    p.add_argument("--features", nargs="+", help="Explicit subset; overrides --feature-set")
    p.add_argument("--test-session", action="append", help="Held-out session UUID; repeatable")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--model", choices=("tree", "forest"), default="tree")
    a = p.parse_args(argv)
    try:
        report = train(a.dataset, a.out, feature_set=a.feature_set, selected=a.features,
                       test_sessions=a.test_session, seed=a.seed, model_kind=a.model)
    except ImportError as exc:
        print(f"Missing training dependency: {exc}. Install requirements-raw.txt", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Training refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: report[k] for k in ("train_windows", "test_windows", "train_sessions",
          "test_sessions", "classification_report", "roc_auc")}, indent=2))
    print(f"Saved PC model and evaluation to {a.out}; ESP32 firmware unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
