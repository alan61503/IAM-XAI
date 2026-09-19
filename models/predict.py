"""Phase 6 CLI: predict risk for one attack path using saved Phase 6 models.

Usage::

    python -m models.predict --path-id synthetic_00042_path_001
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import joblib
import pandas as pd

from .preprocess import align_features, build_feature_matrix, load_dataset

MODELS_DIR = Path(__file__).resolve().parent
PRIMARY_MODEL = "random_forest"
MODEL_NAMES = ("random_forest", "logistic_regression", "xgboost")


def _load_available_models() -> Dict[str, Any]:
    return {
        name: joblib.load(MODELS_DIR / f"{name}.pkl")
        for name in MODEL_NAMES
        if (MODELS_DIR / f"{name}.pkl").exists()
    }


def predict_row(row: pd.DataFrame, models: Dict[str, Any], feature_columns: List[str]) -> Dict[str, Any]:
    """Predict a risk label for one dataset row.

    ``predicted_score`` is the primary model's (Random Forest's) probability for
    the predicted label; ``confidence`` is that same label's average probability
    across every trained model, i.e. how much the models agree.
    """
    X = align_features(build_feature_matrix(row), feature_columns)

    primary = models.get(PRIMARY_MODEL) or next(iter(models.values()))
    primary_probs = dict(zip(primary.classes_, primary.predict_proba(X)[0]))
    predicted_label = max(primary_probs, key=primary_probs.get)

    agreement = []
    for model in models.values():
        model_probs = dict(zip(model.classes_, model.predict_proba(X)[0]))
        agreement.append(model_probs.get(predicted_label, 0.0))

    return {
        "predicted_label": predicted_label,
        "predicted_score": round(float(primary_probs[predicted_label]), 4),
        "confidence": round(float(sum(agreement) / len(agreement)), 4),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m models.predict", description="Predict risk for one attack path.")
    parser.add_argument("--input", default="data/processed/iam_attack_dataset.csv", help="Phase 5 dataset CSV.")
    parser.add_argument("--path-id", required=True, help="path_id from the dataset CSV to predict.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    df = load_dataset(parsed.input)
    match = df[df["path_id"] == parsed.path_id]
    if match.empty:
        print(f"[ERROR] path_id not found: {parsed.path_id}", file=sys.stderr)
        return 1

    models = _load_available_models()
    if not models:
        print("[ERROR] No trained models found. Run `python -m models.train` first.", file=sys.stderr)
        return 1

    feature_columns = joblib.load(MODELS_DIR / "feature_columns.pkl")
    result = {"path_id": parsed.path_id, **predict_row(match.iloc[[0]], models, feature_columns)}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
