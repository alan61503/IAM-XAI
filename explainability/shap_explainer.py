"""Phase 7: SHAP TreeExplainer wrapper around the Phase 6 Random Forest model.

Random Forest is the primary explainability model per CLAUDE.md section 6.3.
``TreeExplainer`` needs no background dataset for tree ensembles.
"""

from pathlib import Path
from typing import Any, List

import joblib
import numpy as np
import shap

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def load_random_forest() -> Any:
    return joblib.load(MODELS_DIR / "random_forest.pkl")


def load_feature_columns() -> List[str]:
    return joblib.load(MODELS_DIR / "feature_columns.pkl")


def build_explainer(model: Any) -> shap.TreeExplainer:
    return shap.TreeExplainer(model)


def shap_values_for_class(explainer: shap.TreeExplainer, X, model: Any, class_label: str) -> np.ndarray:
    """Return the (n_samples, n_features) SHAP contribution matrix for one class.

    Handles both SHAP output conventions: a ``list`` of per-class arrays
    (older versions) and a single ``(n_samples, n_features, n_classes)``
    array (current versions).
    """
    raw = explainer.shap_values(X)
    class_index = list(model.classes_).index(class_label)
    if isinstance(raw, list):
        return raw[class_index]
    return raw[..., class_index]


def base_value_for_class(explainer: shap.TreeExplainer, model: Any, class_label: str) -> float:
    class_index = list(model.classes_).index(class_label)
    expected = explainer.expected_value
    return float(expected[class_index]) if hasattr(expected, "__len__") else float(expected)
