"""Feature extraction for attack paths (Phase 4).

The ``extract_features`` function receives a single path dictionary (as
produced by ``path.path_serializer``) and returns a flat mapping of all
features defined in ``feature_schema.FEATURE_NAMES`` together with the
identifiers required for downstream storage.
"""

from __future__ import annotations

from typing import Dict, List, Set, Any

from .feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from .feature_utils import (
    is_wildcard_action,
    is_wildcard_resource,
    service_from_action,
    safe_div,
    flatten_conditions,
)


def _count_node_types(nodes: List[str]) -> Dict[str, int]:
    """Return counts of users, roles and resources in ``nodes``.

    Nodes are strings prefixed with ``user:``, ``role:`` or ``resource:``.
    Unknown prefixes are ignored.
    """
    counts = {"user": 0, "role": 0, "resource": 0}
    for n in nodes:
        if n.startswith("user:"):
            counts["user"] += 1
        elif n.startswith("role:"):
            counts["role"] += 1
        elif n.startswith("resource:"):
            counts["resource"] += 1
    return counts


def extract_features(path: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single attack‑path dict into a deterministic feature record.

    The returned mapping contains the following top‑level keys:

    * ``scenario_id`` – copied from the input path dict
    * ``path_id`` – copied from the input path dict
    * ``source`` / ``target`` – copied for reference
    * ``features`` – a flat dict matching ``feature_schema.FEATURE_NAMES``

    Missing optional metadata is represented as ``0`` for numeric fields
    and ``None`` for optional string fields (e.g. ``target_sensitive``).
    """
    # ------------------------------------------------------------------
    # Basic identifiers
    # ------------------------------------------------------------------
    scenario_id = path.get("scenario_id")
    path_id = path.get("path_id")
    source = path.get("source")
    target = path.get("target")

    # ------------------------------------------------------------------
    # Path structure
    # ------------------------------------------------------------------
    hops = path.get("hop_count", 0)
    nodes = path.get("nodes", [])
    node_count = len(nodes)
    unique_node_count = len(set(nodes))
    node_type_counts = _count_node_types(nodes)

    # ------------------------------------------------------------------
    # Edge‑type aggregation
    # ------------------------------------------------------------------
    edges = path.get("edges", [])
    edge_type_counts: Dict[str, int] = {}
    for e in edges:
        et = e.get("edge_type")
        edge_type_counts[et] = edge_type_counts.get(et, 0) + 1

    assume_count = edge_type_counts.get("CAN_ASSUME", 0)
    access_count = edge_type_counts.get("CAN_ACCESS", 0)
    modify_count = edge_type_counts.get("CAN_MODIFY", 0)
    passrole_count = edge_type_counts.get("CAN_PASS_ROLE", 0)
    unique_edge_type_count = len(edge_type_counts)

    # ------------------------------------------------------------------
    # Permission breadth
    # ------------------------------------------------------------------
    all_actions: List[str] = []
    all_resources: List[str] = []
    wildcard_action_count = 0
    wildcard_resource_count = 0  # count exact '*'
    any_wildcard_resource_flag = False
    for e in edges:
        acts = e.get("actions", []) or []
        ress = e.get("resources", []) or []
        all_actions.extend(acts)
        all_resources.extend(ress)
        wildcard_action_count += sum(1 for a in acts if is_wildcard_action(a))
        # count exact wildcard resources
        wildcard_resource_count += sum(1 for r in ress if r == "*")
        # flag if any wildcard present in resources
        if any(is_wildcard_resource(r) for r in ress):
            any_wildcard_resource_flag = True
    action_count = len(all_actions)
    unique_action_count = len(set(all_actions))
    resource_pattern_count = len(all_resources)
    unique_resource_pattern_count = len(set(all_resources))
    has_wildcard_action = 1 if wildcard_action_count else 0
    has_wildcard_resource = 1 if any_wildcard_resource_flag else 0

    # ------------------------------------------------------------------
    # Broad permission indicators (metadata driven)
    # ------------------------------------------------------------------
    broad_permission_edge_count = 0
    for e in edges:
        meta = e.get("metadata", {}) or {}
        if meta.get("broad_permission"):
            broad_permission_edge_count += 1
    has_broad_permission = 1 if broad_permission_edge_count else 0

    # ------------------------------------------------------------------
    # Trust / principal features (metadata driven)
    # ------------------------------------------------------------------
    trust_edge_count = assume_count  # per schema correction
    external_principal_count = 0
    service_principal_count = 0
    wildcard_principal_count = 0
    for e in edges:
        meta = e.get("metadata", {}) or {}
        ptype = meta.get("principal_type")
        if ptype == "external":
            external_principal_count += 1
        elif ptype == "service":
            service_principal_count += 1
        elif ptype == "wildcard":
            wildcard_principal_count += 1
    has_external_principal = 1 if external_principal_count else 0
    has_service_principal = 1 if service_principal_count else 0
    has_wildcard_principal = 1 if wildcard_principal_count else 0

    # ------------------------------------------------------------------
    # Condition features
    # ------------------------------------------------------------------
    conditional_edge_count = 0
    condition_operators: Set[str] = set()
    condition_keys: Set[str] = set()
    for e in edges:
        cond = e.get("conditions", {}) or {}
        if cond:
            conditional_edge_count += 1
            ops, keys = flatten_conditions(cond)
            condition_operators.update(ops)
            condition_keys.update(keys)
    has_conditions = 1 if conditional_edge_count else 0
    condition_operator_count = len(condition_operators)
    condition_key_count = len(condition_keys)

    # ------------------------------------------------------------------
    # Effect features
    # ------------------------------------------------------------------
    allow_edge_count = sum(1 for e in edges if e.get("effect") == "Allow")
    deny_edge_count = sum(1 for e in edges if e.get("effect") == "Deny")

    # ------------------------------------------------------------------
    # Target features
    # ------------------------------------------------------------------
    target_type = None
    if isinstance(target, str):
        if target.startswith("user:"):
            target_type = "user"
        elif target.startswith("role:"):
            target_type = "role"
        elif target.startswith("resource:"):
            target_type = "resource"
    target_is_resource = 1 if target_type == "resource" else 0
    target_is_role = 1 if target_type == "role" else 0
    target_is_user = 1 if target_type == "user" else 0

    # Optional target metadata (may be missing entirely)
    target_meta = path.get("target_metadata", {}) or {}
    target_sensitive = target_meta.get("sensitive") if "sensitive" in target_meta else None
    target_criticality = target_meta.get("criticality") if "criticality" in target_meta else None

    # ------------------------------------------------------------------
    # Path composition ratios (safe division)
    # ------------------------------------------------------------------
    role_hop_ratio = safe_div(node_type_counts["role"], hops)
    assume_ratio = safe_div(assume_count, hops)
    access_ratio = safe_div(access_count, hops)
    modify_ratio = safe_div(modify_count, hops)
    passrole_ratio = safe_div(passrole_count, hops)

    permission_edge_count = access_count + modify_count
    # trust_edge_count already defined above (CAN_ASSUME only)

    # ------------------------------------------------------------------
    # Complexity – distinct services
    # ------------------------------------------------------------------
    distinct_services = {service_from_action(a) for a in all_actions}
    distinct_service_count = len(distinct_services)

    # ------------------------------------------------------------------
    # Assemble feature dict following the canonical ordering
    # ------------------------------------------------------------------
    feature_dict: Dict[str, Any] = {
        "hop_count": hops,
        "node_count": node_count,
        "unique_node_count": unique_node_count,
        "user_count": node_type_counts["user"],
        "role_count": node_type_counts["role"],
        "resource_count": node_type_counts["resource"],
        # Edge‑type counts
        "assume_count": assume_count,
        "access_count": access_count,
        "modify_count": modify_count,
        "passrole_count": passrole_count,
        "unique_edge_type_count": unique_edge_type_count,
        "has_assume": 1 if assume_count else 0,
        "has_access": 1 if access_count else 0,
        "has_modify": 1 if modify_count else 0,
        "has_passrole": 1 if passrole_count else 0,
        # Permission breadth
        "action_count": action_count,
        "unique_action_count": unique_action_count,
        "resource_pattern_count": resource_pattern_count,
        "unique_resource_pattern_count": unique_resource_pattern_count,
        "wildcard_action_count": wildcard_action_count,
        "wildcard_resource_count": wildcard_resource_count,
        "has_wildcard_action": has_wildcard_action,
        "has_wildcard_resource": has_wildcard_resource,
        # Broad permission indicators
        "broad_permission_edge_count": broad_permission_edge_count,
        "has_broad_permission": has_broad_permission,
        # Trust / principal
        "trust_edge_count": trust_edge_count,
        "external_principal_count": external_principal_count,
        "service_principal_count": service_principal_count,
        "wildcard_principal_count": wildcard_principal_count,
        "has_external_principal": has_external_principal,
        "has_service_principal": has_service_principal,
        "has_wildcard_principal": has_wildcard_principal,
        # Condition features
        "conditional_edge_count": conditional_edge_count,
        "has_conditions": has_conditions,
        "condition_operator_count": condition_operator_count,
        "condition_key_count": condition_key_count,
        # Effect features
        "allow_edge_count": allow_edge_count,
        "deny_edge_count": deny_edge_count,
        # Target features
        "target_type": target_type,
        "target_is_resource": target_is_resource,
        "target_is_role": target_is_role,
        "target_is_user": target_is_user,
        "target_sensitive": target_sensitive,
        "target_criticality": target_criticality,
        # Ratios & composition
        "role_hop_ratio": role_hop_ratio,
        "assume_ratio": assume_ratio,
        "access_ratio": access_ratio,
        "modify_ratio": modify_ratio,
        "passrole_ratio": passrole_ratio,
        "permission_edge_count": permission_edge_count,
        "distinct_service_count": distinct_service_count,
    }

    # Ensure ordering matches FEATURE_NAMES (extra safety)
    ordered_features = {name: feature_dict.get(name) for name in FEATURE_NAMES}

    return {
        "scenario_id": scenario_id,
        "path_id": path_id,
        "source": source,
        "target": target,
        "features": ordered_features,
    }

# Exported name for the package's __all__
__all__ = ["extract_features"]
