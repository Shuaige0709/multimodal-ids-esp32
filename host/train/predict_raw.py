"""Offline predictions on new feature windows. Load only your own trusted joblib files."""
import argparse
import json
from pathlib import Path
import sys

from host.train.raw_features import SCHEMA
from host.train.train_raw import load_rows


def predict(model_path, dataset, output):
    import joblib
    import numpy as np
    import sklearn
    if Path(output).exists():
        raise FileExistsError(f"Choose a NEW prediction file: {output}")
    model = joblib.load(model_path)
    rows, manifest = load_rows(dataset)
    if model["schema"] != SCHEMA or model["window_ms"] != manifest["window_ms"]:
        raise ValueError("Model and feature schema/window size differ")
    if model["sklearn_version"] != sklearn.__version__:
        raise ValueError("Use the same scikit-learn version as training: " + model["sklearn_version"])
    with Path(output).open("x", encoding="utf-8") as out:
        for offset in range(0, len(rows), 1024):
            chunk = rows[offset:offset+1024]
            good = [r for r in chunk if r["quality_ok"]]
            probabilities = iter(())
            if good:
                X = [[np.nan if r["features"][n] is None else r["features"][n]
                      for n in model["features"]] for r in good]
                probabilities = iter(model["pipeline"].predict_proba(X))
            for r in chunk:
                result = {k: r[k] for k in ("session_id", "boot_id", "window_start_us", "quality_ok", "label")}
                result.update(prediction=None, attack_probability=None)
                if r["quality_ok"]:
                    probability = next(probabilities)
                    result["prediction"] = int(model["pipeline"].classes_[np.argmax(probability)])
                    result["attack_probability"] = float(probability[list(model["pipeline"].classes_).index(1)])
                out.write(json.dumps(result, ensure_ascii=False, allow_nan=False)+"\n")
    return len(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", required=True, help="TRUSTED local model.joblib (pickle can execute code)")
    p.add_argument("--dataset", required=True)
    p.add_argument("--out", required=True, help="NEW predictions JSONL")
    a = p.parse_args(argv)
    try:
        count = predict(a.model, a.dataset, a.out)
    except (ImportError, OSError, ValueError, KeyError) as exc:
        print(f"Prediction failed: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {count} prediction rows to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
