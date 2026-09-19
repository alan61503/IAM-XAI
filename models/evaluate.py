"""Phase 6 evaluation: classification metrics, confusion matrix, feature importance."""

from typing import Any, Dict, List

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

from dataset.schema import RISK_LABELS


def _roc_auc(model, X_test, y_test) -> Any:
    if not hasattr(model, "predict_proba"):
        return None
    proba = model.predict_proba(X_test)
    y_bin = label_binarize(y_test, classes=list(model.classes_))
    if y_bin.shape[1] < 2:
        return None
    return float(roc_auc_score(y_bin, proba, multi_class="ovr", average="weighted"))


def evaluate_model(model, X_test, y_test) -> Dict[str, Any]:
    y_pred = model.predict(X_test)
    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_weighted": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "roc_auc_weighted": _roc_auc(model, X_test, y_test),
        "confusion_matrix": {
            "labels": list(RISK_LABELS),
            "matrix": confusion_matrix(y_test, y_pred, labels=list(RISK_LABELS)).tolist(),
        },
        "classification_report": classification_report(
            y_test, y_pred, labels=list(RISK_LABELS), output_dict=True, zero_division=0
        ),
    }


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
