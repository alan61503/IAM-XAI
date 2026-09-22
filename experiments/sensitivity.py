"""Sensitivity analysis: do the Phase 6 conclusions survive changes to the ground-truth oracle?

The oracle's weights and cut points are modelling assumptions. Each variant
regenerates the dataset under a different oracle (or with label noise), retrains
the models with the same protocol (scenario-grouped split, fixed
hyperparameters), and reports test metrics. If the ranking Random Forest >
Logistic Regression >> static rules and the hybrid's low severe-miss rate hold
across variants, the conclusions don't hinge on one particular weighting.

Usage::

    python -m experiments.sensitivity --count 1500
"""

import argparse
import dataclasses
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from dataset.generator import generate_rows
from dataset.label_generator import DEFAULT_ORACLE, OracleConfig
from dataset.schema import DATASET_COLUMNS, RISK_LABELS
from models.baselines import apply_escalation_floor, predict_rule_based
from models.evaluate import label_ambiguity_ceiling
from models.preprocess import build_feature_matrix, split_dataset
from models.train import _macro_f1, make_model, severe_miss_rate

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "sensitivity_analysis.json"
REPORT_PATH = OUTPUT_PATH.with_suffix(".md")
PERTURBATION = 0.2  # each weight scaled by U(1 - 0.2, 1 + 0.2)


def _scale(value: float, rng: random.Random) -> float:
    return min(1.0, max(0.01, value * rng.uniform(1 - PERTURBATION, 1 + PERTURBATION)))


def perturbed_oracle(seed: int) -> OracleConfig:
    """Every impact/likelihood weight independently scaled by +/-20% (tier order preserved)."""
    rng = random.Random(seed)
    d = DEFAULT_ORACLE
    return dataclasses.replace(
        d,
        tier_impact=tuple(sorted(_scale(v, rng) for v in d.tier_impact)),
        admin_impact=_scale(d.admin_impact, rng),
        policy_modification_impact=_scale(d.policy_modification_impact, rng),
        privileged_pass_role_impact=_scale(d.privileged_pass_role_impact, rng),
        unprivileged_pass_role_impact=_scale(d.unprivileged_pass_role_impact, rng),
        exposure={k: _scale(v, rng) for k, v in d.exposure.items()},
        hop_decay=_scale(d.hop_decay, rng),
        mitigation_factor={k: _scale(v, rng) for k, v in d.mitigation_factor.items()},
    )


def shifted_thresholds(factor: float) -> OracleConfig:
    return dataclasses.replace(DEFAULT_ORACLE, thresholds=tuple((label, round(t * factor, 4)) for label, t in DEFAULT_ORACLE.thresholds))


def variants() -> Dict[str, Dict[str, Any]]:
    return {
        "default": {"oracle": DEFAULT_ORACLE, "label_noise": 0.0},
        "label_noise_5pct": {"oracle": DEFAULT_ORACLE, "label_noise": 0.05},
        "label_noise_10pct": {"oracle": DEFAULT_ORACLE, "label_noise": 0.10},
        "weights_perturbed_a": {"oracle": perturbed_oracle(1), "label_noise": 0.0},
        "weights_perturbed_b": {"oracle": perturbed_oracle(2), "label_noise": 0.0},
        "weights_perturbed_c": {"oracle": perturbed_oracle(3), "label_noise": 0.0},
        "thresholds_minus_10pct": {"oracle": shifted_thresholds(0.9), "label_noise": 0.0},
        "thresholds_plus_10pct": {"oracle": shifted_thresholds(1.1), "label_noise": 0.0},
    }


def run_variant(count: int, workers: int, oracle: OracleConfig, label_noise: float) -> Dict[str, Any]:
    df = pd.DataFrame(generate_rows(count=count, seed=42, workers=workers, oracle=oracle, label_noise=label_noise), columns=DATASET_COLUMNS)
    X_train, _X_val, X_test, y_train, _y_val, y_test = split_dataset(df)
    test_df = df.loc[X_test.index]

    result: Dict[str, Any] = {
        "rows": len(df),
        "label_distribution": {label: round(float((df["risk_label"] == label).mean()), 3) for label in RISK_LABELS},
        "label_ambiguity_ceiling": round(label_ambiguity_ceiling(build_feature_matrix(df), df["risk_label"]), 4),
        "models": {},
    }
    predictions: Dict[str, List[str]] = {}
    for name in ("logistic_regression", "random_forest"):
        model = make_model(name, {"C": 1.0} if name == "logistic_regression" else {})
        predictions[name] = list(model.fit(X_train, y_train).predict(X_test))
    predictions["random_forest+escalation_floor"] = apply_escalation_floor(predictions["random_forest"], test_df)
    predictions["rule_based_baseline"] = predict_rule_based(test_df)

    for name, pred in predictions.items():
        result["models"][name] = {
            "accuracy": round(float((pd.Series(pred, index=y_test.index) == y_test).mean()), 4),
            "f1_macro": round(_macro_f1(y_test, pred), 4),
            "severe_miss_rate": severe_miss_rate(y_test, pred),
        }
    return result


def write_report(results: Dict[str, Any]) -> str:
    lines = [
        "# Sensitivity Analysis",
        "",
        "Each variant regenerates the dataset with a different oracle and retrains (scenario-grouped split).",
        "",
        "| Variant | Ceiling | LR macro F1 | RF macro F1 | Hybrid macro F1 | Rules macro F1 | RF severe-miss | Hybrid severe-miss |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, r in results["variants"].items():
        m = r["models"]
        lines.append(
            f"| {name} | {r['label_ambiguity_ceiling']:.3f} | {m['logistic_regression']['f1_macro']:.3f} | "
            f"{m['random_forest']['f1_macro']:.3f} | {m['random_forest+escalation_floor']['f1_macro']:.3f} | "
            f"{m['rule_based_baseline']['f1_macro']:.3f} | {m['random_forest']['severe_miss_rate']:.1%} | "
            f"{m['random_forest+escalation_floor']['severe_miss_rate']:.1%} |"
        )
    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m experiments.sensitivity", description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=1500, help="Environments per variant (default: 1500).")
    parser.add_argument("--workers", type=int, default=4, help="Generation worker processes (default: 4).")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)
    results: Dict[str, Any] = {"environments_per_variant": parsed.count, "perturbation": PERTURBATION, "variants": {}}
    for name, spec in variants().items():
        print(f"[INFO] Variant {name} ...")
        results["variants"][name] = run_variant(parsed.count, parsed.workers, spec["oracle"], spec["label_noise"])
        results["variants"][name]["oracle"] = dataclasses.asdict(spec["oracle"])
        results["variants"][name]["label_noise"] = spec["label_noise"]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(results, indent=2))
    REPORT_PATH.write_text(write_report(results), encoding="utf-8")
    print(write_report(results))
    print(f"[SUCCESS] Sensitivity analysis written to: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
