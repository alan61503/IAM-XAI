"""Phase 6 CLI: train, tune and evaluate Logistic Regression, Random Forest and XGBoost.

Usage::

    python -m models.train --input data/processed/iam_attack_dataset.csv

Protocol (all splits grouped by ``scenario_id``, ``random_state = 42``):

1. 70/15/15 train/validation/test split.
2. Small hyperparameter grid per model, selected on validation macro-F1.
3. Best configuration refit on train+validation, evaluated once on test.
4. Grouped 5-fold cross-validation on train+validation (mean +/- std).
5. The original CLAUDE.md 5.4 static rules evaluated on the same test set.
6. Leave-one-pattern-out: Random Forest trained without any environment
   containing a given attack pattern, tested on held-out paths exhibiting it.
7. Hybrid IAM-XAI (Random Forest + escalation-primitive floor, see
   ``models/baselines.py``) evaluated alongside, on test and leave-one-pattern-out.
8. Grouped bootstrap 95% CIs and McNemar tests against Random Forest.

Outputs ``evaluation/model_metrics.json`` and ``evaluation/model_report.md``.
"""

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from dataset.schema import RISK_LABELS

from .baselines import apply_escalation_floor, predict_rule_based
from .estimators import LabelEncodedClassifier
from .evaluate import (
    dataset_diagnostics,
    evaluate_model,
    evaluate_predictions,
    feature_importance,
    grouped_bootstrap,
    mcnemar,
)
from .preprocess import GROUP_COLUMN, LABEL_COLUMN, RANDOM_STATE, build_feature_matrix, load_dataset, split_dataset

try:
    import xgboost
    from xgboost import XGBClassifier
    _HAS_XGBOOST = True
except Exception:
    _HAS_XGBOOST = False

MODELS_DIR = Path(__file__).resolve().parent
EVALUATION_DIR = MODELS_DIR.parent / "evaluation"
EVALUATION_PATH = EVALUATION_DIR / "model_metrics.json"
REPORT_PATH = EVALUATION_DIR / "model_report.md"
CV_FOLDS = 5

PARAM_GRIDS: Dict[str, Dict[str, List[Any]]] = {
    "logistic_regression": {"C": [0.1, 1.0, 10.0]},
    "random_forest": {"max_depth": [None, 12], "min_samples_leaf": [1, 5], "class_weight": [None, "balanced"]},
    "xgboost": {"max_depth": [4, 6], "learning_rate": [0.05, 0.1]},
}

# Attack pattern -> dataset column whose flag marks a path as exercising it.
PATTERN_SIGNATURES = {
    "wildcard_action": lambda df: df["wildcard_action"] == 1,
    "wildcard_resource": lambda df: df["wildcard_resource"] == 1,
    "pass_role": lambda df: df["pass_role"] == 1,
    "assume_chain": lambda df: df["role_count"] >= 2,
    "external_trust": lambda df: df["external_trust"] == 1,
    "cross_account": lambda df: df["cross_account"] == 1,
    "wildcard_trust": lambda df: df["wildcard_principal"] == 1,
    "policy_modification": lambda df: df["policy_modification"] == 1,
    "admin_wildcard": lambda df: df["admin_permission"] == 1,
}


def make_model(name: str, params: Dict[str, Any]) -> Any:
    if name == "logistic_regression":
        return make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=RANDOM_STATE, **params))
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1, **params)
    if name == "xgboost":
        return LabelEncodedClassifier(
            XGBClassifier(n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1, eval_metric="mlogloss", tree_method="hist", **params)
        )
    raise ValueError(f"Unknown model: {name}")


def model_names() -> List[str]:
    return ["logistic_regression", "random_forest"] + (["xgboost"] if _HAS_XGBOOST else [])


def build_models() -> Dict[str, Any]:
    """Every available model with the first configuration of its grid."""
    return {name: make_model(name, {k: v[0] for k, v in PARAM_GRIDS[name].items()}) for name in model_names()}


def _param_candidates(name: str) -> List[Dict[str, Any]]:
    grid = PARAM_GRIDS[name]
    return [dict(zip(grid, values)) for values in itertools.product(*grid.values())]


def severe_miss_rate(y_true, y_pred) -> float:
    """Fraction of truly HIGH/CRITICAL paths rated LOW/MEDIUM -- the error that matters in security."""
    severe = {"HIGH", "CRITICAL"}
    pairs = [(t, p) for t, p in zip(y_true, y_pred) if t in severe]
    return round(sum(p not in severe for _, p in pairs) / len(pairs), 4) if pairs else 0.0


def _macro_f1(y_true, y_pred) -> float:
    return float(f1_score(y_true, y_pred, labels=list(RISK_LABELS), average="macro", zero_division=0))


def tune(name: str, X_train, y_train, X_val, y_val) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    results = []
    for params in _param_candidates(name):
        model = make_model(name, params).fit(X_train, y_train)
        results.append({"params": params, "val_f1_macro": round(_macro_f1(y_val, model.predict(X_val)), 4)})
    best = max(results, key=lambda r: r["val_f1_macro"])
    return best["params"], results


def grouped_cv(name: str, params: Dict[str, Any], X, y, groups) -> Dict[str, Any]:
    accs, f1s = [], []
    for train_idx, test_idx in GroupKFold(n_splits=CV_FOLDS).split(X, y, groups):
        model = make_model(name, params).fit(X.iloc[train_idx], y.iloc[train_idx])
        pred = model.predict(X.iloc[test_idx])
        accs.append(accuracy_score(y.iloc[test_idx], pred))
        f1s.append(_macro_f1(y.iloc[test_idx], pred))
    return {
        "folds": CV_FOLDS,
        "accuracy_mean": round(float(np.mean(accs)), 4),
        "accuracy_std": round(float(np.std(accs)), 4),
        "f1_macro_mean": round(float(np.mean(f1s)), 4),
        "f1_macro_std": round(float(np.std(f1s)), 4),
    }


def leave_one_pattern_out(df: pd.DataFrame, X: pd.DataFrame, params: Dict[str, Any]) -> Dict[str, Any]:
    """Random Forest generalization to attack patterns never seen in training environments."""
    y = df[LABEL_COLUMN]
    patterns = df["scenario_patterns"].fillna("none").str.split("|")
    results = {}
    for pattern, signature in PATTERN_SIGNATURES.items():
        has_pattern = patterns.map(lambda ps: pattern in ps)
        test_mask = has_pattern & signature(df)
        if test_mask.sum() < 20:
            continue
        model = make_model("random_forest", params).fit(X[~has_pattern], y[~has_pattern])
        pred = model.predict(X[test_mask])
        hybrid = apply_escalation_floor(list(pred), df[test_mask])
        results[pattern] = {
            "test_paths": int(test_mask.sum()),
            "accuracy": round(float(accuracy_score(y[test_mask], pred)), 4),
            "f1_macro": round(_macro_f1(y[test_mask], pred), 4),
            "hybrid_accuracy": round(float(accuracy_score(y[test_mask], hybrid)), 4),
            "hybrid_f1_macro": round(_macro_f1(y[test_mask], hybrid), 4),
            "severe_miss_rate": severe_miss_rate(y[test_mask], pred),
            "hybrid_severe_miss_rate": severe_miss_rate(y[test_mask], hybrid),
        }
    return results


def _fmt(value: Any) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def write_report(metrics: Dict[str, Any]) -> str:
    diag = metrics["dataset_diagnostics"]
    lines = [
        "# Phase 6 Model Report",
        "",
        f"Dataset: {diag['rows']} attack paths from {diag['scenarios']} environments "
        f"({diag['unique_feature_vectors']} distinct feature vectors). Splits grouped by scenario.",
        "",
        f"- Label distribution: {diag['label_distribution']}",
        f"- Label-ambiguity ceiling (best achievable accuracy): {diag['label_ambiguity_ceiling_accuracy']:.3f}",
        f"- Test rows whose exact feature vector also occurs in train: {diag['test_rows_with_feature_vector_seen_in_train']:.1%}",
        "",
        "## Held-out test set",
        "",
        "| Model | Accuracy | Balanced acc. | Macro F1 | Weighted F1 | ROC-AUC (macro OvR) | Severe-miss rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in metrics["test"].items():
        lines.append(
            f"| {name} | {_fmt(m['accuracy'])} | {_fmt(m['balanced_accuracy'])} | {_fmt(m['f1_macro'])} | "
            f"{_fmt(m['f1_weighted'])} | {_fmt(m['roc_auc_macro_ovr'])} | {m['severe_miss_rate']:.1%} |"
        )
    stats = metrics["statistical_tests"]
    lines += [
        "",
        f"## 95% confidence intervals (grouped bootstrap, {stats['n_boot']} resamples of test scenarios)",
        "",
        "| Model | Accuracy 95% CI | Macro F1 95% CI | Macro F1 gap to RF (95% CI) | McNemar p vs RF |",
        "|---|---|---|---|---|",
    ]
    for name, ci in stats["intervals"].items():
        gap = stats["vs_random_forest"].get(name, {}).get("f1_macro_difference_95ci")
        mc = stats["mcnemar_vs_random_forest"].get(name, {}).get("p_value")
        lines.append(
            f"| {name} | [{ci['accuracy_95ci'][0]:.3f}, {ci['accuracy_95ci'][1]:.3f}] | "
            f"[{ci['f1_macro_95ci'][0]:.3f}, {ci['f1_macro_95ci'][1]:.3f}] | "
            f"{'–' if gap is None else f'[{gap[0]:+.3f}, {gap[1]:+.3f}]'} | {'–' if mc is None else f'{mc:.2g}'} |"
        )
    lines += ["", f"## Grouped {CV_FOLDS}-fold cross-validation (train+val)", "", "| Model | Accuracy | Macro F1 |", "|---|---:|---:|"]
    for name, cv in metrics["grouped_cv"].items():
        lines.append(f"| {name} | {cv['accuracy_mean']:.3f} ± {cv['accuracy_std']:.3f} | {cv['f1_macro_mean']:.3f} ± {cv['f1_macro_std']:.3f} |")
    lines += [
        "",
        "## Leave-one-pattern-out (Random Forest vs. hybrid with escalation floor)",
        "",
        "Severe miss = a truly HIGH/CRITICAL path rated LOW/MEDIUM.",
        "",
        "| Held-out pattern | Test paths | RF accuracy | Hybrid accuracy | RF severe-miss rate | Hybrid severe-miss rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for pattern, r in metrics["leave_one_pattern_out"].items():
        lines.append(
            f"| {pattern} | {r['test_paths']} | {r['accuracy']:.3f} | {r['hybrid_accuracy']:.3f} | "
            f"{r['severe_miss_rate']:.1%} | {r['hybrid_severe_miss_rate']:.1%} |"
        )
    lines += ["", "## Selected hyperparameters", ""]
    for name, search in metrics["hyperparameter_search"].items():
        lines.append(f"- **{name}**: `{search['best_params']}` (validation macro F1 {search['best_val_f1_macro']:.3f})")
    rf_importance = list(metrics["test"]["random_forest"].get("feature_importance", {}).items())[:10]
    if rf_importance:
        lines += ["", "## Random Forest feature importance (top 10)", "", "| Feature | Importance |", "|---|---:|"]
        lines += [f"| {feat} | {imp:.3f} |" for feat, imp in rf_importance]
    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m models.train",
        description="Train Phase 6 risk classifiers on the Phase 5 dataset.",
    )
    parser.add_argument("--input", default="data/processed/iam_attack_dataset.csv", help="Phase 5 dataset CSV.")
    parser.add_argument("--skip-generalization", action="store_true", help="Skip leave-one-pattern-out experiments.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    df = load_dataset(parsed.input).reset_index(drop=True)
    X = build_feature_matrix(df)
    X_train, X_val, X_test, y_train, y_val, y_test = split_dataset(df)
    if not _HAS_XGBOOST:
        print("[WARN] xgboost could not be imported; training only Logistic Regression and Random Forest.", file=sys.stderr)

    X_trval = pd.concat([X_train, X_val])
    y_trval = pd.concat([y_train, y_val])
    groups_trval = df.loc[X_trval.index, GROUP_COLUMN]

    search, test_metrics, cv_metrics, best_params, test_predictions = {}, {}, {}, {}, {}
    for name in model_names():
        print(f"[INFO] Tuning {name} ...")
        params, candidates = tune(name, X_train, y_train, X_val, y_val)
        best_params[name] = params
        search[name] = {"best_params": params, "best_val_f1_macro": max(c["val_f1_macro"] for c in candidates), "candidates": candidates}

        model = make_model(name, params).fit(X_trval, y_trval)
        joblib.dump(model, MODELS_DIR / f"{name}.pkl", compress=3)
        test_metrics[name] = evaluate_model(model, X_test, y_test)
        test_predictions[name] = list(model.predict(X_test))
        if name == "random_forest":
            test_metrics[name]["feature_importance"] = feature_importance(model, list(X.columns))

        print(f"[INFO] Grouped {CV_FOLDS}-fold CV for {name} ...")
        cv_metrics[name] = grouped_cv(name, params, X_trval, y_trval, groups_trval)

    hybrid = "random_forest+escalation_floor"
    test_predictions[hybrid] = apply_escalation_floor(test_predictions["random_forest"], df.loc[X_test.index])
    test_metrics[hybrid] = evaluate_predictions(y_test, test_predictions[hybrid])
    test_predictions["rule_based_baseline"] = predict_rule_based(df.loc[X_test.index])
    test_metrics["rule_based_baseline"] = evaluate_predictions(y_test, test_predictions["rule_based_baseline"])
    for name, pred in test_predictions.items():
        test_metrics[name]["severe_miss_rate"] = severe_miss_rate(y_test, pred)

    print("[INFO] Grouped bootstrap confidence intervals and significance tests ...")
    statistics = grouped_bootstrap(y_test, test_predictions, df.loc[X_test.index, GROUP_COLUMN], reference="random_forest")
    statistics["mcnemar_vs_random_forest"] = {
        name: mcnemar(y_test, test_predictions["random_forest"], pred)
        for name, pred in test_predictions.items()
        if name != "random_forest"
    }
    joblib.dump(list(X.columns), MODELS_DIR / "feature_columns.pkl")

    generalization = {}
    if not parsed.skip_generalization:
        print("[INFO] Leave-one-pattern-out generalization ...")
        generalization = leave_one_pattern_out(df, X, best_params["random_forest"])

    metrics = {
        "metadata": {
            "dataset": str(parsed.input),
            "random_state": RANDOM_STATE,
            "split": "grouped by scenario_id, 70/15/15",
            "scikit_learn_version": sklearn.__version__,
            "xgboost_version": xgboost.__version__ if _HAS_XGBOOST else None,
        },
        "dataset_diagnostics": dataset_diagnostics(df, X, X_train, X_test, LABEL_COLUMN),
        "hyperparameter_search": search,
        "test": test_metrics,
        "grouped_cv": cv_metrics,
        "statistical_tests": statistics,
        "leave_one_pattern_out": generalization,
    }
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_PATH.write_text(json.dumps(metrics, indent=2))
    REPORT_PATH.write_text(write_report(metrics), encoding="utf-8")

    print(f"[SUCCESS] Trained: {model_names()}")
    print(f"[SUCCESS] Metrics written to: {EVALUATION_PATH}")
    print(f"[SUCCESS] Report written to: {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
