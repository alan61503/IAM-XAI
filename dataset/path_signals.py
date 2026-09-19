"""Path-level signals used by the dataset schema that Phase 4's feature vector
does not directly expose (policy modification, cross-account trust, admin
wildcards, and target sensitivity metadata).

These are derived straight from an ``AttackPath.to_dict()``'s ``edges`` list,
which already carries each edge's raw ``actions`` and ``source`` node id.
"""

import re
from typing import Any, Dict, List

_CROSS_ACCOUNT_SOURCE_RE = re.compile(r"^(?:user|role):\d{12}$")

POLICY_MODIFICATION_ACTIONS = {
    "iam:putrolepolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:createpolicyversion",
    "iam:deleterolepolicy",
}


def has_policy_modification(edges: List[Dict[str, Any]]) -> int:
    for edge in edges:
        for action in edge.get("actions", []) or []:
            if action.lower() in POLICY_MODIFICATION_ACTIONS:
                return 1
    return 0


def has_admin_permission(edges: List[Dict[str, Any]]) -> int:
    for edge in edges:
        for action in edge.get("actions", []) or []:
            if action == "*" or action.lower() == "iam:*":
                return 1
    return 0


def has_cross_account(edges: List[Dict[str, Any]]) -> int:
    """A CAN_ASSUME edge whose source id is a bare 12-digit account id (not a
    declared identity) represents trust granted directly to a foreign AWS account.
    """
    for edge in edges:
        if edge.get("edge_type") == "CAN_ASSUME" and _CROSS_ACCOUNT_SOURCE_RE.match(edge.get("source", "")):
            return 1
    return 0


def target_metadata_for(target_node_id: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Build the ``target_metadata`` block that ``feature_extractor`` reads for
    ``target_sensitive``/``target_criticality``, using the scenario's own record
    of which resource/role names it created as sensitive.
    """
    target_name = target_node_id.split(":", 1)[1] if ":" in target_node_id else target_node_id
    sensitive = target_name in meta.get("sensitive_resources", [])
    return {"sensitive": sensitive, "criticality": "high" if sensitive else "low"}
