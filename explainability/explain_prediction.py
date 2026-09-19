"""Phase 7: local explanations -- rank each attack path's top SHAP contributors.

Matches the CLAUDE.md section 7.5 export shape:
``{"path_id", "prediction", "top_factors": [{"feature", "impact"}, ...]}``.
"""

from typing import Any, Dict, List

import pandas as pd

from models.preprocess import align_features, build_feature_matrix, load_dataset

from .shap_explainer import build_explainer, load_feature_columns, load_random_forest, shap_values_for_class

TOP_N = 6


def explain_rows(df: pd.DataFrame, feature_columns: List[str] = None) -> List[Dict[str, Any]]:
    """Explain every row of ``df`` (must include the raw Phase 5 dataset columns plus ``path_id``)."""
    df = df.reset_index(drop=True)
    model = load_random_forest()
    feature_columns = feature_columns or load_feature_columns()
    X = align_features(build_feature_matrix(df), feature_columns)
    predictions = model.predict(X)

    explainer = build_explainer(model)
    results: List[Dict[str, Any]] = []
    for label in set(predictions):
        mask = predictions == label
        contributions = shap_values_for_class(explainer, X.loc[mask], model, label)
        for path_id, row_contrib in zip(df.loc[mask, "path_id"], contributions):
            ranked = sorted(zip(feature_columns, row_contrib), key=lambda kv: abs(kv[1]), reverse=True)[:TOP_N]
            results.append(
                {
                    "path_id": path_id,
                    "prediction": label,
                    "top_factors": [{"feature": name, "impact": round(float(value), 4)} for name, value in ranked],
                }
            )
    return results


def explain_path(path_id: str, dataset_path: str = "data/processed/iam_attack_dataset.csv") -> Dict[str, Any]:
    """Explain a single path, looked up by id from the Phase 5 dataset CSV."""
    df = load_dataset(dataset_path)
    match = df[df["path_id"] == path_id]
    if match.empty:
        raise ValueError(f"path_id not found: {path_id}")
    return explain_rows(match)[0]
