"""Phase 6 evaluation: classification metrics, confusion matrix, feature importance,
dataset diagnostics (leakage and label-ambiguity checks) and statistical tests
(grouped bootstrap confidence intervals, McNemar)."""

from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

from dataset.schema import RISK_LABELS


def _roc_auc(y_true, proba: Optional[np.ndarray], classes: Sequence[str], average: str) -> Optional[float]:
    if proba is None:
        return None
    y_bin = label_binarize(y_true, classes=list(classes))
    present = y_bin.sum(axis=0) > 0
    if present.sum() < 2:
        return None
    return float(roc_auc_score(y_bin[:, present], proba[:, present], average=average))


def evaluate_predictions(
    y_true, y_pred, proba: Optional[np.ndarray] = None, classes: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    labels = list(RISK_LABELS)
    return {
        "n": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "roc_auc_macro_ovr": _roc_auc(y_true, proba, classes or labels, "macro"),
        "roc_auc_weighted_ovr": _roc_auc(y_true, proba, classes or labels, "weighted"),
        "confusion_matrix": {"labels": labels, "matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist()},
        "classification_report": classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0),
    }


def evaluate_model(model, X_test, y_test) -> Dict[str, Any]:
    proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
    return evaluate_predictions(y_test, model.predict(X_test), proba, list(model.classes_))


def feature_importance(model, feature_names: List[str]) -> Dict[str, float]:
    if not hasattr(model, "feature_importances_"):
        return {}
    ranked = sorted(zip(feature_names, model.feature_importances_), key=lambda kv: kv[1], reverse=True)
    return {name: float(value) for name, value in ranked}


def evaluate_models(models: Dict[str, Any], X_test, y_test, feature_names: List[str]) -> Dict[str, Any]:
    """Evaluate every trained model; attach Random Forest's feature importances."""
    report = {}
    for name, model in models.items():
        entry = evaluate_model(model, X_test, y_test)
        if name == "random_forest":
            entry["feature_importance"] = feature_importance(model, feature_names)
        report[name] = entry
    return report


def _row_keys(X: pd.DataFrame) -> pd.Series:
    return pd.util.hash_pandas_object(X.reset_index(drop=True), index=False)


def label_ambiguity_ceiling(X: pd.DataFrame, y: pd.Series) -> float:
    """Best accuracy any model could reach on (X, y): identical feature vectors
    with different labels can't all be classified correctly.
    """
    frame = pd.DataFrame({"key": _row_keys(X), "label": y.reset_index(drop=True)})
    majority = frame.groupby("key")["label"].agg(lambda s: s.value_counts().iloc[0])
    return float(majority.sum() / len(frame))


def dataset_diagnostics(df: pd.DataFrame, X: pd.DataFrame, X_train: pd.DataFrame, X_test: pd.DataFrame, label_column: str) -> Dict[str, Any]:
    train_keys = set(_row_keys(X_train))
    test_keys = _row_keys(X_test)
    return {
        "rows": int(len(df)),
        "scenarios": int(df["scenario_id"].nunique()),
        "mean_paths_per_scenario": round(len(df) / max(1, df["scenario_id"].nunique()), 2),
        "unique_feature_vectors": int(_row_keys(X).nunique()),
        "label_distribution": {label: int((df[label_column] == label).sum()) for label in RISK_LABELS},
        "label_ambiguity_ceiling_accuracy": round(label_ambiguity_ceiling(X, df[label_column]), 4),
        "test_rows_with_feature_vector_seen_in_train": round(float(test_keys.isin(train_keys).mean()), 4),
    }


def _macro_f1_from_cm(cm: np.ndarray) -> float:
    tp = np.diag(cm).astype(float)
    predicted = cm.sum(axis=0)
    actual = cm.sum(axis=1)
    precision = np.divide(tp, predicted, out=np.zeros_like(tp), where=predicted > 0)
    recall = np.divide(tp, actual, out=np.zeros_like(tp), where=actual > 0)
    denom = precision + recall
    f1 = np.divide(2 * precision * recall, denom, out=np.zeros_like(tp), where=denom > 0)
    return float(f1.mean())


def grouped_bootstrap(
    y_true: Sequence[str],
    predictions: Dict[str, Sequence[str]],
    groups: Sequence[str],
    reference: str,
    n_boot: int = 1000,
    seed: int = 42,
) -> Dict[str, Any]:
    """95% confidence intervals by resampling whole scenarios (paths within one
    environment are correlated, so rows can't be resampled independently).

    Also reports, for every model vs. ``reference``, the bootstrap CI of the
    macro-F1 difference and the fraction of resamples where the reference is
    not better (a one-sided bootstrap p-value).
    """
    labels = list(RISK_LABELS)
    index = {label: i for i, label in enumerate(labels)}
    y = np.array([index[v] for v in y_true])
    group_ids, g = np.unique(np.asarray(groups), return_inverse=True)
    n_groups, k = len(group_ids), len(labels)

    per_group_cm = {}
    for name, pred in predictions.items():
        p = np.array([index[v] for v in pred])
        cm = np.zeros((n_groups, k, k), dtype=np.int64)
        np.add.at(cm, (g, y, p), 1)
        per_group_cm[name] = cm

    rng = np.random.default_rng(seed)
    samples = {name: {"accuracy": [], "f1_macro": []} for name in predictions}
    for _ in range(n_boot):
        counts = np.bincount(rng.integers(0, n_groups, n_groups), minlength=n_groups)
        for name, cm in per_group_cm.items():
            total = np.tensordot(counts, cm, axes=1)
            samples[name]["accuracy"].append(np.trace(total) / total.sum())
            samples[name]["f1_macro"].append(_macro_f1_from_cm(total))

    def ci(values: List[float]) -> List[float]:
        return [round(float(np.percentile(values, 2.5)), 4), round(float(np.percentile(values, 97.5)), 4)]

    result: Dict[str, Any] = {"n_boot": n_boot, "resampling_unit": "scenario", "intervals": {}, f"vs_{reference}": {}}
    for name, metric in samples.items():
        result["intervals"][name] = {"accuracy_95ci": ci(metric["accuracy"]), "f1_macro_95ci": ci(metric["f1_macro"])}
        if name != reference:
            diff = np.array(samples[reference]["f1_macro"]) - np.array(metric["f1_macro"])
            result[f"vs_{reference}"][name] = {
                "f1_macro_difference_95ci": ci(list(diff)),
                "p_value_reference_not_better": round(float((diff <= 0).mean()), 4),
            }
    return result


def mcnemar(y_true: Sequence[str], pred_a: Sequence[str], pred_b: Sequence[str]) -> Dict[str, Any]:
    """Exact McNemar test on paired correctness (treats paths as independent)."""
    from scipy.stats import binomtest

    y, a, b = np.asarray(y_true), np.asarray(pred_a), np.asarray(pred_b)
    only_a = int(((a == y) & (b != y)).sum())
    only_b = int(((a != y) & (b == y)).sum())
    n = only_a + only_b
    p_value = float(binomtest(only_a, n, 0.5).pvalue) if n else 1.0
    return {"only_first_correct": only_a, "only_second_correct": only_b, "p_value": p_value}
