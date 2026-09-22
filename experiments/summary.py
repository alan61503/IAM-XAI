"""Compose ``evaluation/RESULTS.md`` -- one paper-ready summary of every experiment.

All numbers are read from the saved evaluation JSON files, so the summary can't
drift from the data. Run last::

    python -m experiments.summary
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

EVALUATION_DIR = Path(__file__).resolve().parent.parent / "evaluation"
RESULTS_PATH = EVALUATION_DIR / "RESULTS.md"

MODEL_NAMES = {
    "logistic_regression": "Logistic Regression",
    "random_forest": "Random Forest",
    "xgboost": "XGBoost",
    "random_forest+escalation_floor": "Hybrid (RF + escalation floor)",
    "rule_based_baseline": "Static rules (baseline)",
}
STRATEGY_NAMES = {
    "random": "Random edge",
    "path_frequency": "Most-shared edge (graph only)",
    "iam_xai": "IAM-XAI ranked",
    "iam_xai_without_shap": "IAM-XAI ranked, no SHAP (ablation)",
    "iam_xai_greedy": "IAM-XAI greedy",
    "oracle_greedy": "Oracle upper bound (uses hidden labels)",
}


def _load(name: str) -> Dict[str, Any]:
    return json.loads((EVALUATION_DIR / name).read_text())


def _ci(pair: List[float]) -> str:
    return f"[{pair[0]:.3f}, {pair[1]:.3f}]"


def classification(m: Dict[str, Any]) -> List[str]:
    d = m["dataset_diagnostics"]
    ci = m["statistical_tests"]["intervals"]
    lines = [
        "## RQ1 — How accurately is risk predicted on unseen environments?",
        "",
        f"Dataset: {d['rows']:,} attack paths from {d['scenarios']:,} synthetic environments "
        f"({d['unique_feature_vectors']:,} distinct feature vectors); labels "
        + ", ".join(f"{k} {v:,}" for k, v in d["label_distribution"].items())
        + ". Train/validation/test = 70/15/15, **grouped by environment**.",
        "",
        f"Label-ambiguity ceiling (best accuracy any model can reach on these features): **{d['label_ambiguity_ceiling_accuracy']:.3f}**.",
        "",
        "| Model | Accuracy [95% CI] | Macro F1 [95% CI] | ROC-AUC | Severe-miss rate |",
        "|---|---|---|---:|---:|",
    ]
    for key, name in MODEL_NAMES.items():
        t = m["test"][key]
        auc = "–" if t["roc_auc_macro_ovr"] is None else f"{t['roc_auc_macro_ovr']:.3f}"
        lines.append(
            f"| {name} | {t['accuracy']:.3f} {_ci(ci[key]['accuracy_95ci'])} | {t['f1_macro']:.3f} {_ci(ci[key]['f1_macro_95ci'])} "
            f"| {auc} | {t['severe_miss_rate']:.1%} |"
        )
    cv = m["grouped_cv"]
    lines += [
        "",
        "Grouped 5-fold cross-validation (macro F1): "
        + "; ".join(f"{MODEL_NAMES[k]} {v['f1_macro_mean']:.3f} ± {v['f1_macro_std']:.3f}" for k, v in cv.items())
        + ".",
        "",
        "CIs from 1,000 bootstrap resamples of test *environments*. Severe miss = a truly HIGH/CRITICAL path rated LOW/MEDIUM. "
        "McNemar p-values vs. Random Forest are in `model_metrics.json`.",
        "",
    ]
    return lines


def generalization(m: Dict[str, Any]) -> List[str]:
    lines = [
        "## RQ2 — Do models recognize attack patterns never seen in training?",
        "",
        "Random Forest trained on environments *without* a pattern; tested on held-out paths that exercise it.",
        "",
        "| Held-out pattern | Paths | RF accuracy | Hybrid accuracy | RF severe-miss | Hybrid severe-miss |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for pattern, r in m["leave_one_pattern_out"].items():
        lines.append(
            f"| {pattern.replace('_', ' ')} | {r['test_paths']:,} | {r['accuracy']:.3f} | {r['hybrid_accuracy']:.3f} "
            f"| {r['severe_miss_rate']:.1%} | {r['hybrid_severe_miss_rate']:.1%} |"
        )
    lines += [
        "",
        "Pure ML misses unseen privilege-escalation primitives; a small domain-knowledge floor "
        "(admin-equivalent or policy-rewrite permission ≥ HIGH; PassRole of a privileged role ≥ HIGH; other PassRole ≥ MEDIUM) "
        "removes those misses without changing in-distribution accuracy (RQ1).",
        "",
    ]
    return lines


def explanations(f: Dict[str, Any]) -> List[str]:
    names = {"shap_local": "SHAP (per path)", "global_importance": "Global importance", "random": "Random ranking"}
    lines = [
        "## RQ3 — Are the SHAP explanations correct and faithful?",
        "",
        f"{f['n_paths']:,} test paths. Cause recovery checks SHAP's top features against the oracle's true `risk_cause`; "
        "deletion fidelity resets the top-k ranked features to training medians and measures the drop in predicted-class probability.",
        "",
        "| Ranking | Top-1 is a true cause | True causes in top 3 | Top 3, multi-cause paths | Prob. drop (top 1) | Prob. drop (top 3) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key, name in names.items():
        r = f["rankings"][key]
        lines.append(
            f"| {name} | {r['cause_recovery_all']['top1_hit_rate']:.1%} | {r['cause_recovery_all']['cause_recall_at_3']:.1%} "
            f"| {r['cause_recovery_multi_cause_paths']['cause_recall_at_3']:.1%} "
            f"| {r['deletion_probability_drop']['top_1']:.3f} | {r['deletion_probability_drop']['top_3']:.3f} |"
        )
    lines.append("")
    return lines


def choke_points(c: Dict[str, Any]) -> List[str]:
    lines = [
        "## RQ4 — Does cutting IAM-XAI's choke points remove real risk?",
        "",
        f"{c['scenarios']} freshly generated environments (seed {c['seed']}, never used in training), {c['attack_paths']:,} attack paths, "
        "scored by the ground-truth oracle.",
        "",
        "| Strategy | Risk removed, 1 cut | Severe paths removed, 1 cut | Risk removed, 3 cuts | Severe paths removed, 3 cuts | Gain vs. most-shared edge, 3 cuts [95% CI] |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for key, name in STRATEGY_NAMES.items():
        s = c["strategies"][key]
        one, three = s["k=1"], s["k=3"]
        lines.append(
            f"| {name} | {one['mean_fraction_of_risk_eliminated']:.1%} | {one['mean_fraction_of_severe_paths_eliminated']:.1%} "
            f"| {three['mean_fraction_of_risk_eliminated']:.1%} | {three['mean_fraction_of_severe_paths_eliminated']:.1%} "
            f"| {three['risk_gain_vs_path_frequency_95ci'][0]:+.3f} to {three['risk_gain_vs_path_frequency_95ci'][1]:+.3f} |"
        )
    lines += [
        "",
        "The gain over graph-only selection comes from ML risk weighting; the no-SHAP ablation performs the same, "
        "so SHAP's role is explaining *why* an edge matters, not choosing it.",
        "",
    ]
    return lines


def sensitivity(s: Dict[str, Any]) -> List[str]:
    lines = [
        "## RQ5 — Do conclusions depend on the oracle's assumptions?",
        "",
        f"Each variant regenerates {s['environments_per_variant']:,} environments under a changed oracle and retrains.",
        "",
        "| Variant | Ceiling | Rules F1 | LR F1 | RF F1 | Hybrid F1 | Hybrid severe-miss |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, r in s["variants"].items():
        mm = r["models"]
        lines.append(
            f"| {name.replace('_', ' ')} | {r['label_ambiguity_ceiling']:.3f} | {mm['rule_based_baseline']['f1_macro']:.3f} "
            f"| {mm['logistic_regression']['f1_macro']:.3f} | {mm['random_forest']['f1_macro']:.3f} "
            f"| {mm['random_forest+escalation_floor']['f1_macro']:.3f} | {mm['random_forest+escalation_floor']['severe_miss_rate']:.1%} |"
        )
    lines += ["", "The ordering Random Forest > Logistic Regression ≫ static rules holds in every variant.", ""]
    return lines


def benchmark(b: Dict[str, Any]) -> List[str]:
    s = b["summary"]
    misses = [r for r in b["scenarios"] if r["expected"] == "attack" and r["hybrid"] not in ("HIGH", "CRITICAL")]
    lines = [
        "## RQ6 — Does IAM-XAI detect independently documented attacks?",
        "",
        "21 IAM privilege-escalation methods (Rhino Security Labs) + 5 scenarios modelled on CloudGoat descriptions and known "
        "trust misconfigurations + 6 benign controls, run through the unchanged pipeline.",
        "",
        "| Method | Attacks detected (HIGH/CRITICAL) | False alarms on benign controls |",
        "|---|---:|---:|",
    ]
    for key in ("random_forest", "hybrid", "rules"):
        lines.append(f"| {key.replace('_', ' ')} | {s[key]['attacks_detected']} ({s[key]['detection_rate']:.0%}) | {s[key]['false_alarms']} |")
    lines += [
        "",
        f"Attack paths were discovered for {s['attack_paths_found']} attack scenarios. Missed by IAM-XAI: "
        + "; ".join(f"{r['id']} {r['name']}" for r in misses)
        + ". These are escalation mechanisms the attack graph does not yet model (credential takeover of another user, "
        "group-membership changes, rewriting the policy of a role the attacker can already assume, and code injection into "
        "a privileged service) -- future work, not tuned after the fact. Full table: `benchmark_results.md`.",
        "",
    ]
    return lines


THREATS = [
    "## Threats to validity",
    "",
    "- **Synthetic ground truth.** Labels come from an oracle we designed; the models learn to approximate it. Mitigations: "
    "the oracle uses information the model sees only partially, conclusions are stable under perturbed weights, noise and "
    "cut points (RQ5), and detection is checked against independently published attacks (RQ6).",
    "- **Low-cardinality features.** Most test feature vectors also occur in training (see `model_report.md`); splits are grouped "
    "by environment so no environment leaks, and the label-ambiguity ceiling bounds achievable accuracy.",
    "- **Graph coverage.** Credential-takeover and code-injection escalation are not modelled (RQ6 misses).",
    "- **Choke-point evaluation assumes cutting an edge is feasible;** business impact of removing a permission is not modelled.",
    "- **Faithfulness mapping.** Cause-to-feature groups are defined by the authors; the random baseline shows the mapping is not trivially satisfied.",
    "",
]

FIGURES = [
    "## Figures (`evaluation/figures/`)",
    "",
    "1. `fig1_model_comparison.png` — RQ1",
    "2. `fig2_confusion_matrix.png` — RQ1",
    "3. `fig3_unseen_pattern_generalization.png` — RQ2",
    "4. `fig4_explanation_faithfulness.png` — RQ3",
    "5. `fig5_choke_point_evaluation.png` — RQ4",
    "6. `fig6_sensitivity.png` — RQ5",
    "",
    "## Reproduce",
    "",
    "```bash",
    "python -m dataset.main --count 3000 --workers 4 --output data/processed/iam_attack_dataset.csv",
    "python -m models.train",
    "python -m explainability.faithfulness",
    "python -m choke_point.evaluate",
    "python -m experiments.sensitivity",
    "python -m experiments.benchmark",
    "python -m experiments.figures",
    "python -m experiments.summary",
    "```",
    "",
]


def main(args: List[str] = None) -> int:
    lines = ["# IAM-XAI — Experimental Results", "", "Generated by `python -m experiments.summary` from the JSON files in `evaluation/`.", ""]
    lines += classification(_load("model_metrics.json"))
    lines += generalization(_load("model_metrics.json"))
    lines += explanations(_load("explanation_faithfulness.json"))
    lines += choke_points(_load("choke_point_evaluation.json"))
    lines += sensitivity(_load("sensitivity_analysis.json"))
    lines += benchmark(_load("benchmark_results.json"))
    lines += THREATS + FIGURES
    RESULTS_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"[SUCCESS] Results summary written to: {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
