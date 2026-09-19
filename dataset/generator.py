"""Phase 5 orchestrator: synthetic scenario -> existing Phase 1-4 pipeline -> labeled row.

Reuses the existing modules as a library (no subprocess/file round-trips):
``parser.normalizer.normalize_scenario`` -> ``graph.graph_builder.build_attack_graph``
-> ``path.path_finder.PathFinder`` -> ``features.feature_extractor.extract_features``.
"""

import random
from typing import Any, Dict, List

from features.feature_extractor import extract_features
from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario
from path.path_finder import PathFinder

from . import label_generator, path_signals
from .scenario_library import REGISTRY

DEFAULT_MAX_HOPS = 6


def _dedupe_and_renumber(paths: List[Any], scenario_id: str) -> List[Any]:
    """Collapse paths that share the same (source, target, node sequence) and
    reassign deterministic path ids, since PassRole targets are probed via a
    second ``find_paths`` call whose internal counter restarts at 1.
    """
    unique = {(p.source, p.target, tuple(p.nodes)): p for p in paths}
    ordered = sorted(unique.values(), key=lambda p: (p.source, p.target, p.hop_count, tuple(p.nodes)))
    for i, p in enumerate(ordered, start=1):
        p.path_id = f"{scenario_id}_path_{i:03d}"
    return ordered


def _discover_paths(graph: Any, meta: Dict[str, Any]) -> List[Any]:
    finder = PathFinder()
    paths = finder.find_paths(graph, max_hops=DEFAULT_MAX_HOPS)

    # iam:PassRole targets a role, which auto-discovery never treats as a
    # target (see path/traversal_policy.py), so probe those explicitly.
    for role_name in meta.get("pass_role_targets", []):
        paths.extend(finder.find_paths(graph, target=f"role:{role_name}", max_hops=DEFAULT_MAX_HOPS))

    return _dedupe_and_renumber(paths, graph.scenario_id)


def _build_row(path_dict: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    path_dict = dict(path_dict)
    path_dict["target_metadata"] = path_signals.target_metadata_for(path_dict["target"], meta)

    record = extract_features(path_dict)
    features = record["features"]
    edges = path_dict["edges"]

    row = {
        "scenario_id": record["scenario_id"],
        "path_id": record["path_id"],
        "source_identity": record["source"],
        "target_resource": record["target"],
        "path_length": features["hop_count"],
        "role_count": features["role_count"],
        "user_count": features["user_count"],
        "assume_role": features["has_assume"],
        "pass_role": features["has_passrole"],
        "wildcard_action": features["has_wildcard_action"],
        "wildcard_resource": features["has_wildcard_resource"],
        "policy_modification": path_signals.has_policy_modification(edges),
        "external_trust": features["has_external_principal"],
        "cross_account": path_signals.has_cross_account(edges),
        "sensitive_target": 1 if features["target_sensitive"] else 0,
        "admin_permission": path_signals.has_admin_permission(edges),
    }
    label, score, attack_type, cause = label_generator.classify(row)
    row.update(risk_label=label, risk_score=score, attack_type=attack_type, risk_cause=cause)
    return row


def generate_rows(count: int, seed: int = 42) -> List[Dict[str, Any]]:
    """Generate ``count`` synthetic scenarios; return one labeled row per attack path found."""
    rng = random.Random(seed)
    scenario_types = list(REGISTRY.keys())
    weights = [REGISTRY[t][1] for t in scenario_types]

    rows: List[Dict[str, Any]] = []
    for i in range(count):
        scenario_type = rng.choices(scenario_types, weights=weights, k=1)[0]
        builder, _ = REGISTRY[scenario_type]
        scenario_id = f"synthetic_{i:05d}"

        raw_scenario, meta = builder(rng, scenario_id)
        graph = build_attack_graph(normalize_scenario(raw_scenario))

        for path in _discover_paths(graph, meta):
            rows.append(_build_row(path.to_dict(), meta))

    return rows
