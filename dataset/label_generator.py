"""Deterministic ground-truth risk labeling, implementing CLAUDE.md section 5.4.

``classify`` is a pure function of the boolean/count columns already assembled
for one dataset row -- no randomness, so the same row always gets the same
label, score, attack type and cause.
"""

from typing import Any, Dict, List, Tuple

_BASE_SCORE = {"LOW": 0.15, "MEDIUM": 0.40, "HIGH": 0.65, "CRITICAL": 0.85}


def _critical_causes(row: Dict[str, Any]) -> List[str]:
    causes = []
    if row["admin_permission"]:
        causes.append("admin_permission")
    if row["external_trust"]:
        causes.append("external_trust")
    if row["cross_account"]:
        causes.append("cross_account")
    if row["policy_modification"]:
        causes.append("policy_modification")
    if row["wildcard_action"] and row["sensitive_target"]:
        causes.append("wildcard_action+sensitive_target")
    return causes


def _high_causes(row: Dict[str, Any]) -> List[str]:
    causes = []
    if row["pass_role"]:
        causes.append("pass_role")
    if row["assume_role"] and row["role_count"] >= 2:
        causes.append("assume_role_chain")
    if row["path_length"] >= 4:
        causes.append("long_privilege_escalation_chain")
    if row["sensitive_target"]:
        causes.append("sensitive_target_reached")
    return causes


def _medium_causes(row: Dict[str, Any]) -> List[str]:
    causes = []
    if row["wildcard_action"]:
        causes.append("wildcard_action")
    if row["wildcard_resource"]:
        causes.append("wildcard_resource")
    return causes


def _attack_type(row: Dict[str, Any]) -> str:
    if row["cross_account"] or (row["assume_role"] and row["role_count"] >= 2):
        return "Lateral Movement"
    if row["pass_role"] or row["admin_permission"] or row["policy_modification"]:
        return "Privilege Escalation"
    return "Data Access"


def classify(row: Dict[str, Any]) -> Tuple[str, float, str, str]:
    """Return ``(risk_label, risk_score, attack_type, risk_cause)`` for one row.

    ``row`` must already contain: path_length, role_count, assume_role,
    pass_role, wildcard_action, wildcard_resource, policy_modification,
    external_trust, cross_account, sensitive_target, admin_permission.
    """
    for label, cause_fn in (("CRITICAL", _critical_causes), ("HIGH", _high_causes), ("MEDIUM", _medium_causes)):
        causes = cause_fn(row)
        if causes:
            bonus = min(0.10, 0.03 * (len(causes) - 1))
            score = round(min(0.98, _BASE_SCORE[label] + bonus), 2)
            return label, score, _attack_type(row), " + ".join(causes)

    return "LOW", _BASE_SCORE["LOW"], _attack_type(row), "read_only_access"
