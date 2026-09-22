"""Single source of truth for turning an attack path into a model-ready feature row.

Used by both the Phase 5 generator (training data) and the Phase 10 dashboard
(inference), so training and serving can never compute features differently.

Only information a real analyzer could observe is used here: the path itself
and the scenario's visible configuration (resource types, sensitivity *tags*).
Ground-truth risk lives in ``label_generator`` and is never an input here.
"""

from typing import Any, Dict, List

from features.feature_extractor import extract_features

from . import path_signals

CLASSIFICATION_LEVELS = ("public", "internal", "confidential", "restricted")
SENSITIVE_LEVEL = 2
UNTAGGED = -1


def _classification_tag(resource: Dict[str, Any]) -> int:
    """Ordinal DataClassification tag (0..3), or -1 when the resource is untagged."""
    tag = str((resource.get("tags") or {}).get("DataClassification", "")).lower()
    return CLASSIFICATION_LEVELS.index(tag) if tag in CLASSIFICATION_LEVELS else UNTAGGED


def _is_admin_statement(stmt: Dict[str, Any]) -> bool:
    """An Allow statement granting ``*`` or ``iam:*`` -- visible administrator power."""
    actions = stmt.get("Action", [])
    actions = [actions] if isinstance(actions, str) else actions
    return stmt.get("Effect", "Allow") == "Allow" and any(a == "*" or a.lower() == "iam:*" for a in actions)


def context_from_scenario(raw_scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the visible context a feature row needs from a raw scenario dict."""
    resources = raw_scenario.get("resources", []) or []
    pass_role_targets: List[str] = []
    identities = [e for key in ("users", "groups", "roles") for e in raw_scenario.get(key, []) or []]
    for identity in identities:
        for stmt in identity.get("permissions", []) or []:
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if not any(a.lower() == "iam:passrole" for a in actions):
                continue
            targets = stmt.get("Resource", [])
            for arn in [targets] if isinstance(targets, str) else targets:
                if ":role/" in arn:
                    pass_role_targets.append(arn.split(":role/", 1)[1])
    tags = {r["name"]: _classification_tag(r) for r in resources if "name" in r}
    privileged_roles = sorted(
        role["name"] for role in raw_scenario.get("roles", []) or [] if any(_is_admin_statement(s) for s in role.get("permissions", []) or [])
    )
    return {
        "sensitive_resources": sorted(
            r["name"] for r in resources if r.get("sensitive") or tags.get(r.get("name"), UNTAGGED) >= SENSITIVE_LEVEL
        ),
        "classification_tags": {name: tag for name, tag in tags.items() if tag != UNTAGGED},
        "resource_types": {r["name"]: r.get("type", "unknown") for r in resources if "name" in r},
        "pass_role_targets": sorted(set(pass_role_targets)),
        "privileged_roles": privileged_roles,
    }


def node_name(node_id: str) -> str:
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def target_service(target_node_id: str, context: Dict[str, Any]) -> str:
    """Service of the path's target: declared resource type, ``iam_role``, or parsed from an ARN."""
    kind = target_node_id.split(":", 1)[0]
    if kind == "role":
        return "iam_role"
    name = node_name(target_node_id)
    declared = context.get("resource_types", {}).get(name)
    if declared:
        return declared
    if name.startswith("arn:aws:"):
        return name.split(":")[2] or "unknown"
    return "unknown"


def build_feature_row(path_dict: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Build one dataset row's identifier and feature columns (no labels)."""
    path_dict = dict(path_dict)
    target_name = node_name(path_dict["target"])
    sensitive = target_name in context.get("sensitive_resources", [])
    path_dict["target_metadata"] = {"sensitive": sensitive, "criticality": "high" if sensitive else "low"}

    record = extract_features(path_dict)
    f = record["features"]
    edges = path_dict["edges"]

    return {
        "scenario_id": record["scenario_id"],
        "path_id": record["path_id"],
        "source_identity": record["source"],
        "target_resource": record["target"],
        # numeric
        "path_length": f["hop_count"],
        "role_count": f["role_count"],
        "user_count": f["user_count"],
        "resource_count": f["resource_count"],
        "action_count": f["action_count"],
        "wildcard_action_count": f["wildcard_action_count"],
        "wildcard_resource_count": f["wildcard_resource_count"],
        "broad_permission_edge_count": f["broad_permission_edge_count"],
        "conditional_edge_count": f["conditional_edge_count"],
        "condition_key_count": f["condition_key_count"],
        "distinct_service_count": f["distinct_service_count"],
        "classification_tag": context.get("classification_tags", {}).get(target_name, UNTAGGED),
        # binary
        "assume_role": f["has_assume"],
        "pass_role": f["has_passrole"],
        "wildcard_action": f["has_wildcard_action"],
        "wildcard_resource": f["has_wildcard_resource"],
        "policy_modification": path_signals.has_policy_modification(edges),
        "external_trust": f["has_external_principal"],
        "cross_account": path_signals.has_cross_account(edges),
        "wildcard_principal": f["has_wildcard_principal"],
        "sensitive_target": 1 if sensitive else 0,
        "admin_permission": path_signals.has_admin_permission(edges),
        "write_access": path_signals.has_write_access(edges),
        "has_conditions": f["has_conditions"],
        "target_privileged": 1 if path_dict["target"].startswith("role:") and target_name in context.get("privileged_roles", []) else 0,
        # categorical
        "target_type": f["target_type"] or "unknown",
        "target_service": target_service(path_dict["target"], context),
    }
