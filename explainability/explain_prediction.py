"""Phase 7: local explanations -- rank each attack path's top SHAP contributors.

Matches the CLAUDE.md section 7.5 export shape:
``{"path_id", "prediction", "top_factors": [{"feature", "impact"}, ...]}``.

Attack-path feature vectors repeat heavily (tens of thousands of paths share a
few thousand distinct vectors), so SHAP is computed once per distinct vector
and mapped back to every path that shares it.
"""

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from models.preprocess import align_features, build_feature_matrix, load_dataset

from .shap_explainer import build_explainer, load_feature_columns, load_random_forest, shap_values_all_classes

TOP_N = 6


def explain_rows(
    df: pd.DataFrame,
    feature_columns: Optional[List[str]] = None,
    model: Any = None,
    top_n: int = TOP_N,
) -> List[Dict[str, Any]]:
    """Explain every row of ``df`` (Phase 5 dataset columns plus ``path_id``), in row order."""
    if df.empty:
        return []
    df = df.reset_index(drop=True)
    model = model if model is not None else load_random_forest()
    feature_columns = feature_columns or load_feature_columns()
    X = align_features(build_feature_matrix(df), feature_columns)

    keys = pd.util.hash_pandas_object(X, index=False).to_numpy()
    unique_keys, first_idx, inverse = np.unique(keys, return_index=True, return_inverse=True)
    X_unique = X.iloc[first_idx]

    predictions = model.predict(X_unique)
    class_index = {label: i for i, label in enumerate(model.classes_)}
    contributions = shap_values_all_classes(build_explainer(model), X_unique)

    unique_factors = []
    for u, label in enumerate(predictions):
        row_contrib = contributions[u, :, class_index[label]]
        order = np.argsort(-np.abs(row_contrib))[:top_n]
        unique_factors.append([{"feature": feature_columns[i], "impact": round(float(row_contrib[i]), 4)} for i in order])

    return [
        {"path_id": path_id, "prediction": predictions[u], "top_factors": unique_factors[u]}
        for path_id, u in zip(df["path_id"], inverse)
    ]


def explain_path(path_id: str, dataset_path: str = "data/processed/iam_attack_dataset.csv") -> Dict[str, Any]:
    """Explain a single path, looked up by id from the Phase 5 dataset CSV."""
    df = load_dataset(dataset_path)
    match = df[df["path_id"] == path_id]
    if match.empty:
        raise ValueError(f"path_id not found: {path_id}")
    return explain_rows(match)[0]
