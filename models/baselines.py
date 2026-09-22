"""Static rule-based baseline: the original CLAUDE.md section 5.4 labeling rules.

Applied to the same visible feature columns the ML models get, this is what a
hand-written policy linter would do. Reporting it next to the learned models
shows how much the ML adds over fixed rules.
"""

from typing import Any, Dict, List

import pandas as pd


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


def rule_based_label(row: Dict[str, Any]) -> str:
    """CRITICAL > HIGH > MEDIUM > LOW, first tier with any matching rule wins."""
    for label, cause_fn in (("CRITICAL", _critical_causes), ("HIGH", _high_causes), ("MEDIUM", _medium_causes)):
        if cause_fn(row):
            return label
    return "LOW"


def predict_rule_based(df: pd.DataFrame) -> List[str]:
    return [rule_based_label(row) for row in df.to_dict("records")]


# Known IAM privilege-escalation primitives and the minimum label they justify,
# regardless of what a learned model predicts (it may never have seen them).
ESCALATION_FLOOR = (
    (lambda row: row["admin_permission"], "HIGH"),
    (lambda row: row["policy_modification"], "HIGH"),
    (lambda row: row["pass_role"] and row["target_privileged"], "HIGH"),
    (lambda row: row["pass_role"], "MEDIUM"),
)
_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def apply_escalation_floor(labels: List[str], df: pd.DataFrame) -> List[str]:
    """Hybrid IAM-XAI: raise ML labels to the floor implied by escalation primitives."""
    floored = []
    for label, row in zip(labels, df.to_dict("records")):
        level = _ORDER.index(label)
        for applies, minimum in ESCALATION_FLOOR:
            if applies(row):
                level = max(level, _ORDER.index(minimum))
        floored.append(_ORDER[level])
    return floored
