"""Phase 8: Choke Point Detection Engine.

Maps SHAP feature attributions and attack graph topology back to specific graph edges
to identify critical bottleneck permissions (choke points) that, if severed, maximize
security risk reduction.
"""

from typing import Any, Dict, List, Optional, Tuple

FEATURE_EDGE_MAP = {
    "assume_role": lambda edge: edge.get("edge_type") == "CAN_ASSUME",
    "assume_count": lambda edge: edge.get("edge_type") == "CAN_ASSUME",
    "assume_ratio": lambda edge: edge.get("edge_type") == "CAN_ASSUME",
    "role_count": lambda edge: edge.get("edge_type") == "CAN_ASSUME",
    "pass_role": lambda edge: edge.get("edge_type") == "CAN_PASS_ROLE",
    "has_passrole": lambda edge: edge.get("edge_type") == "CAN_PASS_ROLE",
    "wildcard_action": lambda edge: any("*" in act for act in edge.get("actions", [])) or edge.get("metadata", {}).get("broad_permission", False),
    "wildcard_resource": lambda edge: any("*" in res for res in edge.get("resources", [])),
    "policy_modification": lambda edge: any(
        act.lower() in [
            "iam:putrolepolicy", "iam:attachrolepolicy", "iam:createpolicyversion",
            "iam:setdefaultpolicyversion", "iam:putuserpolicy", "iam:putgrouppolicy"
        ] or "policy" in act.lower() for act in edge.get("actions", [])
    ),
    "external_trust": lambda edge: edge.get("edge_type") == "CAN_ASSUME" and edge.get("metadata", {}).get("principal_type") == "external",
    "cross_account": lambda edge: edge.get("metadata", {}).get("cross_account", False),
    "sensitive_target": lambda edge: edge.get("edge_type") in ("CAN_ACCESS", "CAN_MODIFY"),
}


def _edge_key(edge: Dict[str, Any]) -> str:
    """Deterministic string key for a graph edge."""
    source = edge.get("source", "")
    target = edge.get("target", "")
    edge_type = edge.get("edge_type", "")
    actions = ",".join(sorted(edge.get("actions", [])))
    return f"{source}->{target}:{edge_type}[{actions}]"


def identify_path_choke_point(path: Dict[str, Any], shap_explanation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Identify the primary choke point edge for a single attack path.

    Args:
        path: Path dictionary containing nodes, edges, hop_count, source, target.
        shap_explanation: Optional SHAP explanation dict with 'top_factors'.

    Returns:
        Dict detailing the selected choke point edge, its score, matching factors, and reasoning.
    """
    edges = path.get("edges", [])
    if not edges:
        return {}

    top_factors = shap_explanation.get("top_factors", []) if shap_explanation else []
    
    edge_scores: List[float] = [0.1] * len(edges)  # Base score for all edges
    edge_matching_factors: List[List[str]] = [[] for _ in edges]

    for factor in top_factors:
        fname = factor.get("feature", "")
        impact = abs(float(factor.get("impact", 0.0)))
        
        matcher = FEATURE_EDGE_MAP.get(fname)
        if matcher:
            for idx, edge in enumerate(edges):
                if matcher(edge):
                    edge_scores[idx] += impact * 2.0
                    edge_matching_factors[idx].append(fname)
        else:
            # Fallback heuristic weighting by edge type
            for idx, edge in enumerate(edges):
                if edge.get("edge_type") in ("CAN_ASSUME", "CAN_PASS_ROLE"):
                    edge_scores[idx] += impact * 0.5
                    edge_matching_factors[idx].append(f"{fname}_structural")

    # Select edge with highest score (prefer middle/pivot edges in case of ties)
    best_idx = 0
    best_score = -1.0
    for idx, score in enumerate(edge_scores):
        if score > best_score:
            best_score = score
            best_idx = idx

    choke_edge = edges[best_idx]
    edge_type = choke_edge.get("edge_type", "")
    source = choke_edge.get("source", "")
    target = choke_edge.get("target", "")
    actions = choke_edge.get("actions", [])
    action_str = ", ".join(actions) if actions else "N/A"
    matching = list(set(edge_matching_factors[best_idx]))

    reasoning = (
        f"Edge '{source}' -> '{target}' via {edge_type} ({action_str}) was identified as the primary choke point. "
        f"Severing this edge interrupts the attack chain before reaching '{path.get('target')}'."
    )

    return {
        "choke_point_id": f"cp_{path.get('path_id', 'path')}",
        "edge": choke_edge,
        "edge_key": _edge_key(choke_edge),
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "actions": actions,
        "choke_score": round(best_score, 4),
        "matched_shap_factors": matching,
        "reasoning": reasoning,
    }


def identify_scenario_choke_points(
    paths: List[Dict[str, Any]],
    explanations: Optional[List[Dict[str, Any]]] = None,
    predictions: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Identify and rank scenario-wide choke point edges (Graph Bottleneck Analysis).

    Args:
        paths: List of attack path dicts for a scenario.
        explanations: Optional list of SHAP explanation dicts matching paths.
        predictions: Optional list of ML prediction dicts matching paths.

    Returns:
        List of ranked choke point dictionaries with path coverage and risk reduction metrics.
    """
    if not paths:
        return []

    explanation_lookup = {exp["path_id"]: exp for exp in (explanations or []) if "path_id" in exp}
    prediction_lookup = {pred["path_id"]: pred for pred in (predictions or []) if "path_id" in pred}

    edge_stats: Dict[str, Dict[str, Any]] = {}

    for path in paths:
        pid = path.get("path_id", "")
        exp = explanation_lookup.get(pid)
        pred = prediction_lookup.get(pid, {})
        
        risk_score = float(pred.get("predicted_score", 0.5 if pred.get("predicted_label") in ("HIGH", "CRITICAL") else 0.2))
        path_choke = identify_path_choke_point(path, exp)

        for edge in path.get("edges", []):
            ekey = _edge_key(edge)
            if ekey not in edge_stats:
                edge_stats[ekey] = {
                    "edge": edge,
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "edge_type": edge.get("edge_type"),
                    "actions": edge.get("actions", []),
                    "paths_blocked": 0,
                    "path_ids": [],
                    "total_risk_blocked": 0.0,
                    "accumulated_shap_score": 0.0,
                    "matched_shap_factors": set(),
                }

            edge_stats[ekey]["paths_blocked"] += 1
            edge_stats[ekey]["path_ids"].append(pid)
            edge_stats[ekey]["total_risk_blocked"] += risk_score

            if path_choke and path_choke.get("edge_key") == ekey:
                edge_stats[ekey]["accumulated_shap_score"] += path_choke.get("choke_score", 0.0)
                edge_stats[ekey]["matched_shap_factors"].update(path_choke.get("matched_shap_factors", []))

    # Calculate final weighted choke score
    ranked: List[Dict[str, Any]] = []
    for idx, (ekey, stat) in enumerate(edge_stats.items()):
        paths_blocked = stat["paths_blocked"]
        risk_blocked = stat["total_risk_blocked"]
        shap_bonus = stat["accumulated_shap_score"]

        # Choke Score Formula: (Risk Blocked) * (1 + 0.3 * (Paths Blocked - 1)) + SHAP Bonus
        final_score = risk_blocked * (1.0 + 0.3 * (paths_blocked - 1)) + (0.5 * shap_bonus)
        
        action_str = ", ".join(stat["actions"]) if stat["actions"] else "N/A"
        reasoning = (
            f"Severing '{stat['source']}' -> '{stat['target']}' ({stat['edge_type']}) neutralizes "
            f"{paths_blocked} attack path(s), reducing total scenario risk by {round(risk_blocked, 2)}."
        )

        ranked.append(
            {
                "choke_point_id": f"cp_scenario_{idx + 1:03d}",
                "edge": stat["edge"],
                "edge_key": ekey,
                "source": stat["source"],
                "target": stat["target"],
                "edge_type": stat["edge_type"],
                "actions": stat["actions"],
                "paths_blocked": paths_blocked,
                "path_ids": stat["path_ids"],
                "total_risk_blocked": round(risk_blocked, 4),
                "choke_score": round(final_score, 4),
                "matched_shap_factors": list(stat["matched_shap_factors"]),
                "reasoning": reasoning,
            }
        )

    # Sort descending by choke_score
    ranked.sort(key=lambda item: item["choke_score"], reverse=True)
    return ranked
