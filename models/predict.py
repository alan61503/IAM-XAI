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
import numpy as np
import pandas as pd

from .preprocess import align_features, build_feature_matrix, load_dataset

MODELS_DIR = Path(__file__).resolve().parent
PRIMARY_MODEL = "random_forest"
# Severity weight per class, for a probability-weighted expected risk in [0, 1].
LABEL_SEVERITY = {"LOW": 0.15, "MEDIUM": 0.40, "HIGH": 0.65, "CRITICAL": 0.85}
MODEL_NAMES = ("random_forest", "logistic_regression", "xgboost")


def _load_available_models() -> Dict[str, Any]:
    return {
        name: joblib.load(MODELS_DIR / f"{name}.pkl")
        for name in MODEL_NAMES
        if (MODELS_DIR / f"{name}.pkl").exists()
    }


def predict_frame(rows: pd.DataFrame, models: Dict[str, Any], feature_columns: List[str]) -> List[Dict[str, Any]]:
    """Predict risk labels for every dataset row in one batch per model.

    ``predicted_score`` is the primary model's (Random Forest's) probability for
    the predicted label; ``confidence`` is that same label's average probability
    across every trained model, i.e. how much the models agree; ``expected_risk``
    is the primary model's probability-weighted class severity (a confident
    LOW prediction has low expected risk, unlike its ``predicted_score``).
    """
    if rows.empty:
        return []
    X = align_features(build_feature_matrix(rows), feature_columns)

    primary = models.get(PRIMARY_MODEL) or next(iter(models.values()))
    primary_proba = primary.predict_proba(X)
    labels = primary.classes_[primary_proba.argmax(axis=1)]

    agreement = []
    for model in models.values():
        proba = model.predict_proba(X)
        column = {label: i for i, label in enumerate(model.classes_)}
        agreement.append([proba[i, column[label]] if label in column else 0.0 for i, label in enumerate(labels)])
    confidence = np.mean(agreement, axis=0)
    severity = np.array([LABEL_SEVERITY[label] for label in primary.classes_])
    expected_risk = primary_proba @ severity

    return [
        {
            "predicted_label": str(label),
            "predicted_score": round(float(primary_proba[i].max()), 4),
            "confidence": round(float(confidence[i]), 4),
            "expected_risk": round(float(expected_risk[i]), 4),
        }
        for i, label in enumerate(labels)
    ]


def predict_row(row: pd.DataFrame, models: Dict[str, Any], feature_columns: List[str]) -> Dict[str, Any]:
    """Predict a risk label for one dataset row (see ``predict_frame``)."""
    return predict_frame(row, models, feature_columns)[0]


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
