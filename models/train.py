"""Phase 6 CLI: train Logistic Regression, Random Forest, and XGBoost risk classifiers.

Usage::

    python -m models.train --input data/processed/iam_attack_dataset.csv
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from .evaluate import evaluate_models
from .preprocess import RANDOM_STATE, load_dataset, split_dataset

try:
    from xgboost import XGBClassifier
    _HAS_XGBOOST = True
except Exception:
    _HAS_XGBOOST = False

MODELS_DIR = Path(__file__).resolve().parent
EVALUATION_PATH = MODELS_DIR.parent / "evaluation" / "model_metrics.json"


def build_models() -> dict:
    models = {
        "logistic_regression": LogisticRegression(max_iter=1000, random_state=RANDOM_STATE),
        "random_forest": RandomForestClassifier(random_state=RANDOM_STATE),
    }
    if _HAS_XGBOOST:
        models["xgboost"] = XGBClassifier(random_state=RANDOM_STATE, eval_metric="mlogloss")
    return models


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m models.train",
        description="Train Phase 6 risk classifiers on the Phase 5 dataset.",
    )
    parser.add_argument("--input", default="data/processed/iam_attack_dataset.csv", help="Phase 5 dataset CSV.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    df = load_dataset(parsed.input)
    X_train, _X_val, X_test, y_train, _y_val, y_test = split_dataset(df)

    models = build_models()
    if not _HAS_XGBOOST:
        print(
            "[WARN] xgboost could not be imported in this environment; training only "
            "Logistic Regression and Random Forest.",
            file=sys.stderr,
        )

    for name, model in models.items():
        model.fit(X_train, y_train)
        joblib.dump(model, MODELS_DIR / f"{name}.pkl")

    joblib.dump(list(X_train.columns), MODELS_DIR / "feature_columns.pkl")

    metrics = evaluate_models(models, X_test, y_test, feature_names=list(X_train.columns))
    EVALUATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVALUATION_PATH.write_text(json.dumps(metrics, indent=2))

    print(f"[SUCCESS] Trained: {list(models.keys())}")
    print(f"[SUCCESS] Metrics written to: {EVALUATION_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
