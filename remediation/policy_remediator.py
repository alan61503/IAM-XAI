"""Phase 9: Policy Remediator.

Applies precision least-privilege remediation patches to raw IAM JSON scenario definitions
based on Phase 8 choke point recommendations.
"""

import copy
from typing import Any, Dict, List, Tuple


def _parse_entity_name(node_id: str) -> Tuple[str, str]:
    """Parse node_id like 'role:RoleA' into ('role', 'RoleA')."""
    if ":" in node_id:
        kind, name = node_id.split(":", 1)
        return kind.lower(), name
    return "unknown", node_id


def remediate_choke_point(
    scenario: Dict[str, Any],
    choke_point: Dict[str, Any],
    action_type: str = "AUTO",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Apply a least-privilege remediation patch for a given choke point.

    Args:
        scenario: Raw IAM scenario dictionary.
        choke_point: Choke point dictionary from Phase 8.
        action_type: 'AUTO', 'REVOKE_TRUST', 'ADD_MFA', or 'RESTRICT_PERMISSIONS'.

    Returns:
        Tuple of (remediated_scenario, remediation_summary_dict).
    """
    remediated = copy.deepcopy(scenario)
    source_kind, source_name = _parse_entity_name(choke_point.get("source", ""))
    target_kind, target_name = _parse_entity_name(choke_point.get("target", ""))
    edge_type = choke_point.get("edge_type", "")
    actions = choke_point.get("actions", [])

    patch_applied = False
    patch_type = ""
    description = ""
    target_entity = ""

    # 1. Handle CAN_ASSUME edge (Trust Policy remediation on target role)
    if edge_type == "CAN_ASSUME":
        target_entity = f"role:{target_name}"
        for role in remediated.get("roles", []):
            if role.get("name") == target_name or role.get("arn", "").endswith(target_name):
                trust_pol = role.get("trust_policy", {})
                statements = trust_pol.get("Statement", []) if isinstance(trust_pol, dict) else []

                new_statements = []
                for stmt in statements:
                    effect = stmt.get("Effect", "Allow")
                    principal = stmt.get("Principal", {})
                    stmt_actions = stmt.get("Action", [])
                    if isinstance(stmt_actions, str):
                        stmt_actions = [stmt_actions]

                    # Match statement allowing AssumeRole to source
                    is_match = effect == "Allow" and any("assumerole" in act.lower() for act in stmt_actions)
                    if is_match:
                        if action_type in ("AUTO", "REVOKE_TRUST"):
                            patch_applied = True
                            patch_type = "REVOKE_TRUST_POLICY_STATEMENT"
                            description = f"Removed trust statement in role '{target_name}' permitting assumption by '{source_name}'."
                            continue  # Omit statement
                        elif action_type == "ADD_MFA":
                            patch_applied = True
                            patch_type = "ADD_MFA_CONDITION"
                            description = f"Added Multi-Factor Authentication requirement to trust policy in role '{target_name}'."
                            cond = stmt.setdefault("Condition", {})
                            cond.setdefault("Bool", {})["aws:MultiFactorAuthPresent"] = "true"
                            new_statements.append(stmt)
                    else:
                        new_statements.append(stmt)

                if isinstance(trust_pol, dict):
                    trust_pol["Statement"] = new_statements

    # 2. Handle CAN_PASS_ROLE, CAN_ACCESS, CAN_MODIFY (Permission Policy remediation on source entity)
    else:
        target_entity = f"{source_kind}:{source_name}"
        entities_to_check = remediated.get("roles", []) if source_kind == "role" else remediated.get("users", [])
        for entity in entities_to_check:
            if entity.get("name") == source_name:
                permissions = entity.get("permissions", [])
                new_permissions = []
                for stmt in permissions:
                    effect = stmt.get("Effect", "Allow")
                    stmt_actions = stmt.get("Action", [])
                    if isinstance(stmt_actions, str):
                        stmt_actions = [stmt_actions]

                    # Check if statement actions match choke point actions
                    match_action = any(act in stmt_actions or "*" in stmt_actions for act in actions)
                    if effect == "Allow" and match_action:
                        patch_applied = True
                        if "*" in stmt_actions or any("*" in a for a in stmt_actions):
                            patch_type = "RESTRICT_WILDCARD_PERMISSIONS"
                            # Replace wildcard with explicit specific actions
                            stmt["Action"] = [a for a in stmt_actions if "*" not in a] + [
                                a for a in actions if "*" not in a
                            ]
                            if not stmt["Action"]:
                                stmt["Action"] = ["s3:GetObject"] if edge_type == "CAN_ACCESS" else ["sts:AssumeRole"]
                            description = f"Restricted wildcard actions in '{source_name}' policy to specific least-privilege actions."
                            new_permissions.append(stmt)
                        else:
                            patch_type = "REMOVE_EXCESSIVE_PERMISSION_STATEMENT"
                            description = f"Removed permission statement in '{source_name}' permitting '{edge_type}' to '{target_name}'."
                            continue  # Omit statement
                    else:
                        new_permissions.append(stmt)

                entity["permissions"] = new_permissions

    summary = {
        "choke_point_id": choke_point.get("choke_point_id", ""),
        "patch_applied": patch_applied,
        "patch_type": patch_type or "NO_PATCH_MATCHED",
        "target_entity": target_entity,
        "edge_type": edge_type,
        "description": description or f"No direct policy statement modified for edge {edge_type}.",
    }

    return remediated, summary
