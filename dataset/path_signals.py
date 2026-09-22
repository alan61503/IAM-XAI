"""Path-level signals used by the dataset schema that Phase 4's feature vector
does not directly expose (policy modification, cross-account trust, admin
wildcards, write access, mitigating condition kinds).

These are derived straight from an ``AttackPath.to_dict()``'s ``edges`` list,
which already carries each edge's raw ``actions``, ``conditions`` and ``source``.
"""

import re
from typing import Any, Dict, List, Set

_CROSS_ACCOUNT_SOURCE_RE = re.compile(r"^(?:user|role):\d{12}$")

POLICY_MODIFICATION_ACTIONS = {
    "iam:putrolepolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:deleterolepolicy",
}

# Condition key (lower-cased) -> mitigating control kind.
CONDITION_KINDS = {
    "aws:multifactorauthpresent": "mfa",
    "aws:sourceip": "source_ip",
    "sts:externalid": "external_id",
}


def is_policy_modification_action(action: str) -> bool:
    return action.lower() in POLICY_MODIFICATION_ACTIONS


def has_policy_modification(edges: List[Dict[str, Any]]) -> int:
    for edge in edges:
        for action in edge.get("actions", []) or []:
            if is_policy_modification_action(action):
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


def has_write_access(edges: List[Dict[str, Any]]) -> int:
    return 1 if any(edge.get("edge_type") == "CAN_MODIFY" for edge in edges) else 0


def condition_kinds(edges: List[Dict[str, Any]]) -> List[str]:
    """Mitigating control kinds present on the path, one entry per conditional edge and kind."""
    kinds: List[str] = []
    for edge in edges:
        found: Set[str] = set()
        for inner in (edge.get("conditions") or {}).values():
            if isinstance(inner, dict):
                found.update(CONDITION_KINDS[k.lower()] for k in inner if k.lower() in CONDITION_KINDS)
        kinds.extend(sorted(found))
    return kinds
