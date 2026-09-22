"""Phase 5 orchestrator: synthetic environment -> existing Phase 1-4 pipeline -> labeled rows.

Reuses the existing modules as a library (no subprocess/file round-trips):
``parser.normalizer.normalize_scenario`` -> ``graph.graph_builder.build_attack_graph``
-> ``path.path_finder.PathFinder`` -> ``dataset.row_builder.build_feature_row``
-> ``dataset.label_generator.assess``.

Every scenario gets its own seeded RNG derived from ``(seed, index)``, so the
dataset is reproducible and scenarios can be generated in parallel.
"""

import random
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Any, Dict, List

from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario
from path.path_finder import PathFinder

from . import label_generator
from .row_builder import build_feature_row, context_from_scenario, node_name
from .scenario_library import TIER_NAMES, build_environment
from .schema import RISK_LABELS

DEFAULT_MAX_HOPS = 6
# Caps how many paths one environment contributes, so a single densely
# connected environment (e.g. one with a public-trust admin role) can't dominate.
# When over the cap, paths are sampled class-balanced (see ``_cap_rows``), since
# benign internal-access paths vastly outnumber attack paths in every environment.
DEFAULT_MAX_PATHS_PER_SCENARIO = 30


def scenario_rng(seed: int, index: int) -> random.Random:
    return random.Random(seed * 1_000_003 + index)


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


def discover_paths(graph: Any, context: Dict[str, Any], max_hops: int = DEFAULT_MAX_HOPS) -> List[Any]:
    finder = PathFinder()
    paths = finder.find_paths(graph, max_hops=max_hops)

    # iam:PassRole targets a role, which auto-discovery never treats as a
    # target (see path/traversal_policy.py), so probe those explicitly.
    for role_name in context.get("pass_role_targets", []):
        paths.extend(finder.find_paths(graph, target=f"role:{role_name}", max_hops=max_hops))

    return _dedupe_and_renumber(paths, graph.scenario_id)


def _target_classification(target: str, meta: Dict[str, Any]) -> str:
    name = node_name(target)
    if target.startswith("role:"):
        return "privileged_role" if name in meta.get("privileged_roles", []) else "service_role"
    tier = meta.get("resource_tiers", {}).get(name, label_generator.DEFAULT_TIER)
    return TIER_NAMES[tier]


def _apply_label_noise(label: str, rng: random.Random, rate: float) -> str:
    """With probability ``rate``, move the label one step to an adjacent class."""
    if rate <= 0 or rng.random() >= rate:
        return label
    idx = RISK_LABELS.index(label)
    step = rng.choice([-1, 1]) if 0 < idx < len(RISK_LABELS) - 1 else (1 if idx == 0 else -1)
    return RISK_LABELS[idx + step]


def build_labeled_row(
    path_dict: Dict[str, Any],
    context: Dict[str, Any],
    meta: Dict[str, Any],
    oracle: label_generator.OracleConfig = label_generator.DEFAULT_ORACLE,
) -> Dict[str, Any]:
    row = build_feature_row(path_dict, context)
    label, score, attack_type, cause = label_generator.assess(path_dict, row, meta, oracle)
    row.update(
        risk_label=label,
        risk_score=score,
        attack_type=attack_type,
        risk_cause=cause,
        scenario_patterns="|".join(meta.get("patterns", [])) or "none",
        target_classification=_target_classification(path_dict["target"], meta),
    )
    return row


def generate_scenario_rows(
    index: int,
    seed: int = 42,
    max_paths_per_scenario: int = DEFAULT_MAX_PATHS_PER_SCENARIO,
    label_noise: float = 0.0,
    oracle: label_generator.OracleConfig = label_generator.DEFAULT_ORACLE,
) -> List[Dict[str, Any]]:
    """Build scenario ``index`` and return one labeled row per (capped) attack path."""
    rng = scenario_rng(seed, index)
    raw_scenario, meta = build_environment(rng, f"synthetic_{index:05d}")
    context = context_from_scenario(raw_scenario)
    graph = build_attack_graph(normalize_scenario(raw_scenario))

    rows = [build_labeled_row(p.to_dict(), context, meta, oracle) for p in discover_paths(graph, context)]
    rows = _cap_rows(rows, max_paths_per_scenario, rng)
    for row in rows:
        row["risk_label"] = _apply_label_noise(row["risk_label"], rng, label_noise)
    return rows


def _cap_rows(rows: List[Dict[str, Any]], cap: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Keep at most ``cap`` rows: an equal share per risk label first, then
    random leftovers to fill the cap. Returned in original (path id) order.
    """
    if len(rows) <= cap:
        return rows
    by_label: Dict[str, List[int]] = {label: [] for label in RISK_LABELS}
    for idx, row in enumerate(rows):
        by_label[row["risk_label"]].append(idx)
    share = cap // len(RISK_LABELS)
    keep = set()
    for indices in by_label.values():
        keep.update(rng.sample(indices, min(share, len(indices))))
    leftovers = [i for i in range(len(rows)) if i not in keep]
    keep.update(rng.sample(leftovers, cap - len(keep)))
    return [rows[i] for i in sorted(keep)]


def generate_rows(
    count: int,
    seed: int = 42,
    max_paths_per_scenario: int = DEFAULT_MAX_PATHS_PER_SCENARIO,
    label_noise: float = 0.0,
    workers: int = 1,
    oracle: label_generator.OracleConfig = label_generator.DEFAULT_ORACLE,
) -> List[Dict[str, Any]]:
    """Generate ``count`` synthetic environments; return one labeled row per attack path found."""
    job = partial(
        generate_scenario_rows,
        seed=seed,
        max_paths_per_scenario=max_paths_per_scenario,
        label_noise=label_noise,
        oracle=oracle,
    )
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            per_scenario = list(pool.map(job, range(count), chunksize=max(1, count // (workers * 8))))
    else:
        per_scenario = [job(i) for i in range(count)]
    return [row for rows in per_scenario for row in rows]
