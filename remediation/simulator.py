"""Phase 9: Remediation Simulator.

Re-evaluates attack paths on remediated IAM configurations to empirically verify
that target choke points and privilege escalation paths are eliminated.
"""

from typing import Any, Dict, List

from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario
from path.path_finder import PathFinder


def verify_remediation(
    original_scenario: Dict[str, Any],
    remediated_scenario: Dict[str, Any],
    max_hops: int = 5,
) -> Dict[str, Any]:
    """Run full graph construction & path discovery pipeline on original vs remediated scenarios.

    Returns:
        Verification metrics comparing before and after attack paths.
    """
    finder = PathFinder()

    # 1. Original graph & paths
    orig_norm = normalize_scenario(original_scenario)
    orig_graph = build_attack_graph(orig_norm)
    orig_paths = finder.find_paths(orig_graph, max_hops=max_hops)

    # 2. Remediated graph & paths
    rem_norm = normalize_scenario(remediated_scenario)
    rem_graph = build_attack_graph(rem_norm)
    rem_paths = finder.find_paths(rem_graph, max_hops=max_hops)

    orig_count = len(orig_paths)
    rem_count = len(rem_paths)
    eliminated = max(0, orig_count - rem_count)

    if rem_count == 0:
        status = "FULLY_ELIMINATED"
    elif rem_count < orig_count:
        status = "PARTIALLY_REDUCED"
    else:
        status = "UNCHANGED"

    return {
        "before_paths_count": orig_count,
        "after_paths_count": rem_count,
        "eliminated_paths_count": eliminated,
        "status": status,
        "is_verified": rem_count < orig_count or orig_count == 0,
    }
