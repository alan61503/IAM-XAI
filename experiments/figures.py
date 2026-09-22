"""Publication figures from the saved evaluation JSON files (``evaluation/figures/*.png``).

Run after ``models.train``, ``explainability.faithfulness``,
``choke_point.evaluate`` and ``experiments.sensitivity``::

    python -m experiments.figures
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

EVALUATION_DIR = Path(__file__).resolve().parent.parent / "evaluation"
FIGURES_DIR = EVALUATION_DIR / "figures"

# Validated categorical slots (colorblind-safe as a set), plus neutral inks.
SERIES = ("#2a78d6", "#eb6834", "#1baf7a")
NEUTRAL = "#8c8b87"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e6e5e1"
SURFACE = "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK_SECONDARY,
    "axes.titlecolor": INK,
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "axes.titlelocation": "left",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "xtick.color": INK_SECONDARY,
    "ytick.color": INK_SECONDARY,
    "font.size": 9,
    "legend.frameon": False,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

PRETTY = {
    "logistic_regression": "Logistic Regression",
    "random_forest": "Random Forest",
    "xgboost": "XGBoost",
    "random_forest+escalation_floor": "Hybrid (RF + escalation floor)",
    "rule_based_baseline": "Static rules (baseline)",
    "iam_xai": "IAM-XAI (ranked)",
    "iam_xai_without_shap": "IAM-XAI without SHAP",
    "iam_xai_greedy": "IAM-XAI (greedy)",
    "path_frequency": "Most-shared edge",
    "random": "Random edge",
    "oracle_greedy": "Oracle upper bound",
    "shap_local": "SHAP (per path)",
    "global_importance": "Global importance",
    "random_ranking": "Random ranking",
}


def _load(name: str) -> Dict[str, Any]:
    return json.loads((EVALUATION_DIR / name).read_text())


def _grid(ax, axis: str = "x") -> None:
    ax.grid(axis=axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _legend_below(ax, ncol: int = 2) -> None:
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=ncol, fontsize=8)


def _save(fig, name: str) -> Path:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    path = FIGURES_DIR / name
    fig.savefig(path)
    plt.close(fig)
    return path


def _grouped_barh(ax, categories: Sequence[str], series: Dict[str, Sequence[float]], fmt: str = "{:.2f}") -> None:
    """Horizontal grouped bars, one color per series in fixed order, value at each tip."""
    n = len(series)
    height = 0.8 / n
    y = np.arange(len(categories))
    for i, (name, values) in enumerate(series.items()):
        offsets = y - 0.4 + height * (i + 0.5)
        bars = ax.barh(offsets, values, height=height * 0.9, color=SERIES[i], label=name)
        for bar, value in zip(bars, values):
            ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2, " " + fmt.format(value),
                    va="center", ha="left", fontsize=7.5, color=INK_SECONDARY)
    ax.set_yticks(y, categories)
    ax.invert_yaxis()
    _grid(ax)


def model_comparison() -> Path:
    metrics = _load("model_metrics.json")
    order = ["rule_based_baseline", "logistic_regression", "random_forest", "xgboost", "random_forest+escalation_floor"]
    intervals = metrics["statistical_tests"]["intervals"]
    values = [metrics["test"][m]["f1_macro"] for m in order]
    lo = [values[i] - intervals[m]["f1_macro_95ci"][0] for i, m in enumerate(order)]
    hi = [intervals[m]["f1_macro_95ci"][1] - values[i] for i, m in enumerate(order)]

    fig, ax = plt.subplots(figsize=(6.2, 2.8))
    y = np.arange(len(order))
    ax.barh(y, values, height=0.55, color=[NEUTRAL] + [SERIES[0]] * (len(order) - 1))
    ax.errorbar(values, y, xerr=[lo, hi], fmt="none", ecolor=INK, elinewidth=1, capsize=3)
    for yi, v, h in zip(y, values, hi):
        ax.text(v + h + 0.01, yi, f"{v:.3f}", va="center", fontsize=8, color=INK_SECONDARY)
    ceiling = metrics["dataset_diagnostics"]["label_ambiguity_ceiling_accuracy"]
    ax.axvline(ceiling, color=INK_SECONDARY, linewidth=1)
    ax.text(ceiling + 0.008, 0.5, f"accuracy\nceiling\n{ceiling:.3f}", fontsize=7, color=INK_SECONDARY, va="center", ha="left")
    ax.set_yticks(y, [PRETTY[m] for m in order])
    ax.invert_yaxis()
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Test macro F1 (95% CI, scenario-grouped bootstrap)")
    ax.set_title("Risk classification on unseen environments")
    _grid(ax)
    return _save(fig, "fig1_model_comparison.png")


def confusion() -> Path:
    cm = _load("model_metrics.json")["test"]["random_forest"]["confusion_matrix"]
    labels, matrix = cm["labels"], np.array(cm["matrix"])
    share = matrix / matrix.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(3.8, 3.3))
    ax.imshow(share, cmap="Blues", vmin=0, vmax=1)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{share[i, j]:.0%}\n({matrix[i, j]})", ha="center", va="center", fontsize=7.5,
                    color="white" if share[i, j] > 0.55 else INK)
    ax.set_xticks(range(len(labels)), labels)
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Random Forest confusion matrix (row %)")
    for spine in ax.spines.values():
        spine.set_visible(False)
    return _save(fig, "fig2_confusion_matrix.png")


def generalization() -> Path:
    lopo = _load("model_metrics.json")["leave_one_pattern_out"]
    patterns = list(lopo)
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    _grouped_barh(
        ax,
        [p.replace("_", " ") for p in patterns],
        {
            "Random Forest": [100 * lopo[p]["severe_miss_rate"] for p in patterns],
            "Hybrid (RF + escalation floor)": [100 * lopo[p]["hybrid_severe_miss_rate"] for p in patterns],
        },
        fmt="{:.1f}%",
    )
    ax.set_xlim(0, 110)
    ax.set_xlabel("Severe-miss rate (%): truly HIGH/CRITICAL paths rated LOW/MEDIUM")
    ax.set_title("Attack patterns never seen in training")
    _legend_below(ax)
    return _save(fig, "fig3_unseen_pattern_generalization.png")


def faithfulness() -> Path:
    rankings = _load("explanation_faithfulness.json")["rankings"]
    order = ["shap_local", "global_importance", "random"]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8))
    _grouped_barh(
        axes[0],
        [PRETTY.get(r + "_ranking", PRETTY[r]) for r in order],
        {
            "Top-1 hits a true cause": [rankings[r]["cause_recovery_all"]["top1_hit_rate"] for r in order],
            "True causes in top 3": [rankings[r]["cause_recovery_all"]["cause_recall_at_3"] for r in order],
        },
    )
    axes[0].set_xlim(0, 1.15)
    axes[0].set_title("Recovering the true risk cause")
    _legend_below(axes[0], ncol=1)
    _grouped_barh(
        axes[1],
        [PRETTY.get(r + "_ranking", PRETTY[r]) for r in order],
        {
            "Top-1 feature removed": [rankings[r]["deletion_probability_drop"]["top_1"] for r in order],
            "Top-3 features removed": [rankings[r]["deletion_probability_drop"]["top_3"] for r in order],
        },
    )
    axes[1].set_xlim(0, 0.7)
    axes[1].set_yticklabels([])
    axes[1].set_title("Faithfulness: confidence drop")
    _legend_below(axes[1], ncol=1)
    fig.tight_layout()
    return _save(fig, "fig4_explanation_faithfulness.png")


def choke_points() -> Path:
    strategies = _load("choke_point_evaluation.json")["strategies"]
    order = ["random", "path_frequency", "iam_xai", "iam_xai_greedy", "oracle_greedy"]
    fig, ax = plt.subplots(figsize=(6.2, 3.0))
    _grouped_barh(
        ax,
        [PRETTY[s] for s in order],
        {
            "1 edge cut": [100 * strategies[s]["k=1"]["mean_fraction_of_risk_eliminated"] for s in order],
            "3 edges cut": [100 * strategies[s]["k=3"]["mean_fraction_of_risk_eliminated"] for s in order],
        },
        fmt="{:.1f}%",
    )
    ax.set_xlim(0, 65)
    ax.set_xlabel("Ground-truth risk eliminated (%), 200 unseen environments")
    ax.set_title("Choke-point remediation")
    _legend_below(ax)
    return _save(fig, "fig5_choke_point_evaluation.png")


def sensitivity() -> Path:
    variants = _load("sensitivity_analysis.json")["variants"]
    names = list(variants)
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    y = np.arange(len(names))
    ax.hlines(y, 0, 1, color=GRID, linewidth=0.8)
    for i, (model, label) in enumerate([("random_forest", "Random Forest"), ("logistic_regression", "Logistic Regression"), ("rule_based_baseline", "Static rules")]):
        ax.scatter([variants[n]["models"][model]["f1_macro"] for n in names], y, s=36, color=SERIES[i],
                   edgecolor=SURFACE, linewidth=1.5, zorder=3, label=label)
    ax.scatter([variants[n]["label_ambiguity_ceiling"] for n in names], y, marker="|", s=120, color=INK, zorder=4,
               label="Accuracy ceiling (label ambiguity)")
    ax.set_yticks(y, [n.replace("_", " ") for n in names])
    ax.invert_yaxis()
    ax.set_xlim(0.3, 1.0)
    ax.set_xlabel("Test macro F1")
    ax.set_title("Robustness to oracle assumptions")
    ax.legend(loc="lower left", fontsize=7.5, ncol=2, bbox_to_anchor=(0, -0.42))
    _grid(ax)
    return _save(fig, "fig6_sensitivity.png")


def main(args: List[str] = None) -> int:
    for build in (model_comparison, confusion, generalization, faithfulness, choke_points, sensitivity):
        print(f"[SUCCESS] {build()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
