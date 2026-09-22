"""Phase 8 evaluation: does cutting IAM-XAI's choke point remove more real risk?

On freshly generated environments (a seed never used for training), every
attack path is scored by the ground-truth oracle. Each strategy then picks
``k`` edges to cut; a path is eliminated when any of its edges is cut. We report
the fraction of total ground-truth risk and of HIGH/CRITICAL paths eliminated.

Strategies:

- ``iam_xai`` -- Phase 8 ranking from ML predictions + SHAP explanations.
- ``iam_xai_without_shap`` -- same, with no SHAP input (ablation).
- ``iam_xai_greedy`` -- for k > 1, greedily picks edges by *predicted* risk
  still uncovered, so cuts don't overlap on the same paths (deployable).
- ``path_frequency`` -- edge shared by the most attack paths (graph-only).
- ``random`` -- a random edge on some attack path.
- ``oracle_greedy`` -- greedy on ground-truth risk (an upper bound, not a
  deployable method: it needs the hidden labels).

Usage::

    python -m choke_point.evaluate --scenarios 200
"""

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Set

import joblib
import numpy as np
import pandas as pd

from dataset.generator import build_labeled_row, discover_paths, scenario_rng
from dataset.row_builder import context_from_scenario
from dataset.scenario_library import build_environment
from explainability.explain_prediction import explain_rows
from graph.graph_builder import build_attack_graph
from models.predict import MODELS_DIR, PRIMARY_MODEL, _load_available_models, predict_frame
from parser.normalizer import normalize_scenario

from .choke_finder import _edge_key, greedy_edge_cut, identify_scenario_choke_points, select_choke_point_set

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "choke_point_evaluation.json"
EVALUATION_SEED = 2024  # disjoint from the training seed (42)
BUDGETS = (1, 3)
SEVERE = {"HIGH", "CRITICAL"}


def _build_scenarios(n: int, seed: int, max_paths: int) -> List[Dict[str, Any]]:
    scenarios = []
    for i in range(n):
        rng = scenario_rng(seed, i)
        raw, meta = build_environment(rng, f"choke_eval_{i:04d}")
        context = context_from_scenario(raw)
        paths = [p.to_dict() for p in discover_paths(build_attack_graph(normalize_scenario(raw)), context)]
        if len(paths) > max_paths:
            paths = rng.sample(paths, max_paths)
        if paths:
            scenarios.append({"paths": paths, "rows": [build_labeled_row(p, context, meta) for p in paths]})
    return scenarios


def _removed(path_edges: List[Set[str]], cut: Sequence[str]) -> np.ndarray:
    cut_set = set(cut)
    return np.array([bool(edges & cut_set) for edges in path_edges])


def _paired_ci(values: List[float], baseline: List[float], seed: int, n_boot: int = 2000) -> List[float]:
    """Bootstrap 95% CI of the mean per-scenario difference (values - baseline)."""
    diff = np.array(values) - np.array(baseline)
    rng = np.random.default_rng(seed)
    means = [diff[rng.integers(0, len(diff), len(diff))].mean() for _ in range(n_boot)]
    return [round(float(np.percentile(means, 2.5)), 4), round(float(np.percentile(means, 97.5)), 4)]


def evaluate(n_scenarios: int = 200, seed: int = EVALUATION_SEED, max_paths: int = 400) -> Dict[str, Any]:
    models = _load_available_models()
    feature_columns = joblib.load(MODELS_DIR / "feature_columns.pkl")
    scenarios = _build_scenarios(n_scenarios, seed, max_paths)

    frame = pd.DataFrame([row for s in scenarios for row in s["rows"]])
    predictions = [{"path_id": pid, **p} for pid, p in zip(frame["path_id"], predict_frame(frame, models, feature_columns))]
    explanations = explain_rows(frame, feature_columns=feature_columns, model=models[PRIMARY_MODEL])

    rng = random.Random(seed)
    scores: Dict[str, Dict[int, Dict[str, List[float]]]] = {}
    offset = 0
    for s in scenarios:
        n = len(s["paths"])
        preds, exps = predictions[offset:offset + n], explanations[offset:offset + n]
        offset += n

        path_edges = [{_edge_key(e) for e in p["edges"]} for p in s["paths"]]
        risk = np.array([row["risk_score"] for row in s["rows"]])
        severe = np.array([row["risk_label"] in SEVERE for row in s["rows"]])
        all_edges = sorted(set().union(*path_edges))
        frequency = Counter(edge for edges in path_edges for edge in edges)

        rankings: Dict[str, Callable[[int], List[str]]] = {
            "iam_xai": lambda k: [c["edge_key"] for c in identify_scenario_choke_points(s["paths"], exps, preds)][:k],
            "iam_xai_without_shap": lambda k: [c["edge_key"] for c in identify_scenario_choke_points(s["paths"], None, preds)][:k],
            "iam_xai_greedy": lambda k: select_choke_point_set(s["paths"], preds, k),
            "path_frequency": lambda k: sorted(all_edges, key=lambda e: (-frequency[e], e))[:k],
            "random": lambda k: rng.sample(all_edges, min(k, len(all_edges))),
            "oracle_greedy": lambda k: greedy_edge_cut(path_edges, risk, k),
        }
        for name, pick in rankings.items():
            for k in BUDGETS:
                removed = _removed(path_edges, pick(k))
                entry = scores.setdefault(name, {}).setdefault(k, {"risk": [], "severe": []})
                entry["risk"].append(float(risk[removed].sum() / risk.sum()))
                if severe.any():
                    entry["severe"].append(float(removed[severe].mean()))

    summary = {
        name: {
            f"k={k}": {
                "mean_fraction_of_risk_eliminated": round(float(np.mean(v["risk"])), 4),
                "mean_fraction_of_severe_paths_eliminated": round(float(np.mean(v["severe"])), 4),
                "risk_gain_vs_path_frequency_95ci": _paired_ci(v["risk"], scores["path_frequency"][k]["risk"], seed),
            }
            for k, v in per_k.items()
        }
        for name, per_k in scores.items()
    }
    return {
        "scenarios": len(scenarios),
        "attack_paths": int(len(frame)),
        "seed": seed,
        "max_paths_per_scenario": max_paths,
        "strategies": summary,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m choke_point.evaluate", description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=int, default=200, help="Fresh environments to evaluate (default: 200).")
    parser.add_argument("--seed", type=int, default=EVALUATION_SEED, help=f"Generation seed (default: {EVALUATION_SEED}).")
    parser.add_argument("--output", default=str(OUTPUT_PATH), help="Output JSON path.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)
    result = evaluate(parsed.scenarios, parsed.seed)
    output = Path(parsed.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result["strategies"], indent=2))
    print(f"[SUCCESS] Choke point evaluation ({result['scenarios']} environments) written to: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
