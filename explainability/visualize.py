"""Phase 7: SHAP plot generation. Everything is saved under evaluation/shap/.

Global plots (summary, feature-importance bar) run over a sample of the
dataset and average |SHAP| across the four risk classes into one view.
Local plots (waterfall, force, decision) explain one attack path's
predicted class.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import shap

from models.preprocess import align_features, build_feature_matrix, load_dataset

from .shap_explainer import base_value_for_class, build_explainer, load_feature_columns, load_random_forest, shap_values_for_class

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "evaluation" / "shap"


def _save(filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / filename
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    return out_path


def generate_global_plots(dataset_path: str = "data/processed/iam_attack_dataset.csv", sample_size: int = 200) -> None:
    """Summary plot and feature-importance bar plot over a sample of the dataset."""
    df = load_dataset(dataset_path)
    model = load_random_forest()
    feature_columns = load_feature_columns()

    sample = df.sample(n=min(sample_size, len(df)), random_state=42)
    X = align_features(build_feature_matrix(sample), feature_columns)

    explainer = build_explainer(model)
    raw = explainer.shap_values(X)
    combined = sum(abs(raw[..., i]) for i in range(len(model.classes_))) / len(model.classes_)

    shap.summary_plot(combined, X, show=False)
    _save("summary_plot.png")

    shap.summary_plot(combined, X, plot_type="bar", show=False)
    _save("feature_importance_bar.png")


def generate_local_plots(path_id: str, dataset_path: str = "data/processed/iam_attack_dataset.csv") -> None:
    """Waterfall, force, and decision plots for one attack path's predicted class."""
    df = load_dataset(dataset_path)
    match = df[df["path_id"] == path_id]
    if match.empty:
        raise ValueError(f"path_id not found: {path_id}")

    model = load_random_forest()
    feature_columns = load_feature_columns()
    X = align_features(build_feature_matrix(match.iloc[[0]]), feature_columns)
    prediction = model.predict(X)[0]

    explainer = build_explainer(model)
    contributions = shap_values_for_class(explainer, X, model, prediction)[0]
    base_value = base_value_for_class(explainer, model, prediction)

    explanation = shap.Explanation(
        values=contributions,
        base_values=base_value,
        data=X.iloc[0].to_numpy(),
        feature_names=list(X.columns),
    )

    shap.plots.waterfall(explanation, show=False)
    _save(f"{path_id}_waterfall.png")

    shap.plots.force(base_value, contributions, X.iloc[0], matplotlib=True, show=False)
    _save(f"{path_id}_force.png")

    shap.decision_plot(base_value, contributions, X.iloc[0], show=False)
    _save(f"{path_id}_decision.png")
