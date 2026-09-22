"""Phase 7 evaluation: are the SHAP explanations right, and faithful to the model?

Two complementary checks on held-out (test-split) attack paths:

1. **Cause recovery** -- every synthetic path carries its ground-truth
   ``risk_cause`` (e.g. ``restricted_data + external_trust``). Each cause maps
   to the model features that express it; we measure how often the top SHAP
   feature belongs to a true cause (top-1 hit) and what fraction of true causes
   appear among the top-3 SHAP features (cause recall@3).
2. **Deletion fidelity** -- replacing a path's top-k ranked features with
   reference values (training median / mode) should lower the model's
   probability for its predicted class. A faithful ranking causes a larger drop.

Both are compared against a *global* ranking (same mean-|SHAP| order for every
path) and a *random* ranking, so per-path explanations must beat a one-size-fits-all
explanation to count as adding value.

Usage::

    python -m explainability.faithfulness --sample 3000
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Set

import numpy as np
import pandas as pd

from models.preprocess import RANDOM_STATE, align_features, build_feature_matrix, load_dataset, split_dataset

from .explain_prediction import explain_rows
from .shap_explainer import load_feature_columns, load_random_forest

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "explanation_faithfulness.json"
TOP_K = (1, 3)

_TIER_CAUSES = ("public_data", "internal_data", "confidential_data", "restricted_data")

# Ground-truth driver -> predicate over model feature names that express it.
DRIVER_FEATURES: Dict[str, Callable[[str], bool]] = {
    "data_classification": lambda f: f in {"classification_tag", "sensitive_target"} or f.startswith("target_service_"),
    "write_access": lambda f: f == "write_access",
    "admin_permission": lambda f: f in {"admin_permission", "wildcard_action", "wildcard_action_count", "broad_permission_edge_count"},
    "policy_modification": lambda f: f in {"policy_modification", "target_service_iam_policy"},
    "pass_role": lambda f: f in {"pass_role", "target_type_role", "target_service_iam_role"},
    "external_trust": lambda f: f == "external_trust",
    "cross_account": lambda f: f in {"cross_account", "external_trust"},
    "public_trust": lambda f: f == "wildcard_principal",
    "long_chain": lambda f: f in {"path_length", "role_count"},
    "mitigation": lambda f: f in {"has_conditions", "conditional_edge_count", "condition_key_count"},
}


def cause_drivers(risk_cause: str) -> Set[str]:
    """Map a ``risk_cause`` string from the oracle to driver names."""
    drivers: Set[str] = set()
    for token in risk_cause.split(" + "):
        if token.endswith("_mitigated"):
            drivers.add("mitigation")
        elif token.startswith("pass_role_to_"):
            drivers.add("pass_role")
        elif token in DRIVER_FEATURES:
            drivers.add(token)
        elif token.startswith(_TIER_CAUSES):
            drivers.add("data_classification")
            if token.endswith("_write"):
                drivers.add("write_access")
    return drivers


def _driver_hits(ranking: Sequence[str], drivers: Set[str], k: int) -> Set[str]:
    return {d for d in drivers if any(DRIVER_FEATURES[d](f) for f in ranking[:k])}


def cause_recovery(rankings: List[Sequence[str]], causes: Sequence[str]) -> Dict[str, float]:
    top1, recall3 = [], []
    for ranking, cause in zip(rankings, causes):
        drivers = cause_drivers(cause)
        if not drivers:
            continue
        top1.append(bool(_driver_hits(ranking, drivers, 1)))
        recall3.append(len(_driver_hits(ranking, drivers, 3)) / len(drivers))
    return {"top1_hit_rate": round(float(np.mean(top1)), 4), "cause_recall_at_3": round(float(np.mean(recall3)), 4), "n": len(top1)}


def deletion_drop(model: Any, X: pd.DataFrame, rankings: List[Sequence[str]], reference: pd.Series, k: int) -> float:
    """Mean drop in predicted-class probability after resetting each row's top-k features."""
    base = model.predict_proba(X)
    predicted = base.argmax(axis=1)
    perturbed = X.copy()
    for i, ranking in enumerate(rankings):
        cols = list(ranking[:k])
        perturbed.iloc[i, [X.columns.get_loc(c) for c in cols]] = reference[cols].to_numpy()
    after = model.predict_proba(perturbed)
    rows = np.arange(len(X))
    return round(float((base[rows, predicted] - after[rows, predicted]).mean()), 4)


def evaluate(df: pd.DataFrame, sample: int = 3000) -> Dict[str, Any]:
    model = load_random_forest()
    feature_columns = load_feature_columns()
    X_train, _, X_test, *_ = split_dataset(df)
    test = df.loc[X_test.index]
    if len(test) > sample:
        test = test.sample(n=sample, random_state=RANDOM_STATE)
    test = test.reset_index(drop=True)

    X = align_features(build_feature_matrix(test), feature_columns)
    train_X = align_features(X_train, feature_columns)
    reference = train_X.median()
    explanations = explain_rows(test, feature_columns=feature_columns, model=model, top_n=len(feature_columns))

    shap_rankings = [[f["feature"] for f in e["top_factors"]] for e in explanations]
    global_importance: Dict[str, float] = {c: 0.0 for c in feature_columns}
    for e in explanations:
        for f in e["top_factors"]:
            global_importance[f["feature"]] += abs(f["impact"])
    global_order = sorted(feature_columns, key=lambda c: -global_importance[c])
    rng = np.random.default_rng(RANDOM_STATE)
    rankings = {
        "shap_local": shap_rankings,
        "global_importance": [global_order] * len(test),
        "random": [list(rng.permutation(feature_columns)) for _ in range(len(test))],
    }

    causes = list(test["risk_cause"])
    correct = np.array([e["prediction"] for e in explanations]) == test["risk_label"].to_numpy()
    multi = np.array([len(cause_drivers(c)) >= 2 for c in causes])

    def subset(values: List[Any], mask: np.ndarray) -> List[Any]:
        return [v for v, keep in zip(values, mask) if keep]

    result: Dict[str, Any] = {"n_paths": len(test), "split": "test (grouped by scenario)", "rankings": {}}
    for name, ranking in rankings.items():
        result["rankings"][name] = {
            "cause_recovery_all": cause_recovery(ranking, causes),
            "cause_recovery_correct_predictions": cause_recovery(subset(ranking, correct), subset(causes, correct)),
            "cause_recovery_multi_cause_paths": cause_recovery(subset(ranking, multi), subset(causes, multi)),
            "deletion_probability_drop": {f"top_{k}": deletion_drop(model, X, ranking, reference, k) for k in TOP_K},
        }
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m explainability.faithfulness", description=__doc__.splitlines()[0])
    parser.add_argument("--input", default="data/processed/iam_attack_dataset.csv", help="Phase 5 dataset CSV.")
    parser.add_argument("--sample", type=int, default=3000, help="Test paths to evaluate (default: 3000).")
    parser.add_argument("--output", default=str(OUTPUT_PATH), help="Output JSON path.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)
    result = evaluate(load_dataset(parsed.input).reset_index(drop=True), sample=parsed.sample)
    output = Path(parsed.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result["rankings"], indent=2))
    print(f"[SUCCESS] Explanation faithfulness written to: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
