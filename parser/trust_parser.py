"""Trust policy parsing and normalization for IAM role trust relationships."""

from typing import Any, Dict, List, Union
from parser.policy_parser import (
    IAMValidationError,
    _validate_effect,
    _normalize_string_or_list,
    _extract_conditions,
)


def _extract_principal_sources(
    principal: Any, context: str = ""
) -> List[str]:
    """Extract list of principal identifier strings from Principal block.

    Supports:
    - Wildcard string: "*" -> ["*"]
    - Dict with types such as "AWS", "Service", "Federated":
        - "AWS": "UserA" -> ["UserA"]
        - "AWS": ["UserA", "RoleB"] -> ["UserA", "RoleB"]
        - "Service": "ec2.amazonaws.com" -> ["ec2.amazonaws.com"]
        - "AWS": "*" -> ["*"]
    """
    ctx_prefix = f"[{context}] " if context else ""
    if principal is None:
        raise IAMValidationError(f"{ctx_prefix}Missing 'Principal' in trust policy statement.")

    if isinstance(principal, str):
        p_str = principal.strip()
        if not p_str:
            raise IAMValidationError(f"{ctx_prefix}'Principal' cannot be an empty string.")
        return [p_str]

    if isinstance(principal, dict):
        if not principal:
            raise IAMValidationError(f"{ctx_prefix}'Principal' object cannot be empty.")
        sources: List[str] = []
        for p_type, p_val in principal.items():
            if not isinstance(p_type, str) or not p_type.strip():
                raise IAMValidationError(f"{ctx_prefix}Principal type must be a non-empty string.")
            normalized_vals = _normalize_string_or_list(
                p_val, f"Principal.{p_type}", context=context
            )
            sources.extend(normalized_vals)
        return sources

    if isinstance(principal, list):
        # In case a list of principal strings is provided
        return _normalize_string_or_list(principal, "Principal", context=context)

    raise IAMValidationError(
        f"{ctx_prefix}'Principal' must be a string or dictionary, got {type(principal).__name__}."
    )


def parse_trust_statement(
    statement: Dict[str, Any], target_role: str
) -> List[Dict[str, Any]]:
    """Parse a single trust policy statement and return a list of trust relationships.

    One relationship is created per principal identity specified.

    Args:
        statement: Dictionary representing a trust policy statement.
        target_role: Name of the role that trusts the principal.

    Returns:
        List of normalized trust relationship dictionaries:
        [
            {
                "source": "UserA",
                "effect": "Allow" | "Deny",
                "actions": ["sts:AssumeRole"],
                "target": target_role,
                "conditions": {...}
            },
            ...
        ]
    """
    context = f"trust_policy for role '{target_role}'"

    if not isinstance(statement, dict):
        raise IAMValidationError(
            f"[{context}] Trust policy statement must be a dictionary, got {type(statement).__name__}."
        )

    # Validate Effect
    if "Effect" not in statement and "effect" not in statement:
        raise IAMValidationError(f"[{context}] Missing 'Effect' in trust policy statement.")
    raw_effect = statement.get("Effect") if "Effect" in statement else statement.get("effect")
    effect = _validate_effect(raw_effect, context=context)

    # Validate Principal
    raw_principal = statement.get("Principal") if "Principal" in statement else statement.get("principal")
    sources = _extract_principal_sources(raw_principal, context=context)

    # Validate Action
    raw_action = None
    if "Action" in statement:
        raw_action = statement.get("Action")
    elif "action" in statement:
        raw_action = statement.get("action")
    elif "actions" in statement:
        raw_action = statement.get("actions")
    else:
        raise IAMValidationError(f"[{context}] Missing 'Action' in trust policy statement.")
    actions = _normalize_string_or_list(raw_action, "Action", context=context)

    # Extract conditions
    conditions = _extract_conditions(statement, context=context)

    # Create one relationship per source principal
    relationships = []
    for source in sources:
        relationships.append(
            {
                "source": source,
                "effect": effect,
                "actions": actions,
                "target": target_role,
                "conditions": conditions,
            }
        )

    return relationships


def parse_trust_policy(
    raw_trust_policy: Union[Dict[str, Any], List[Any]], target_role: str
) -> List[Dict[str, Any]]:
    """Parse a role's trust policy into normalized trust relationships.

    Accepts:
    - Standard AWS IAM Trust Policy object with 'Statement'
    - Single statement dictionary
    - List of statement dictionaries

    Args:
        raw_trust_policy: The trust policy structure.
        target_role: Name of the role containing this trust policy.

    Returns:
        List of normalized trust relationship dictionaries.
    """
    if raw_trust_policy is None:
        return []

    context = f"role '{target_role}'"
    statements_to_process: List[Dict[str, Any]] = []

    if isinstance(raw_trust_policy, dict):
        if "Statement" in raw_trust_policy:
            stmt = raw_trust_policy["Statement"]
            if isinstance(stmt, list):
                statements_to_process.extend(stmt)
            elif isinstance(stmt, dict):
                statements_to_process.append(stmt)
            else:
                raise IAMValidationError(
                    f"[{context}] 'Statement' in trust policy must be a list or dictionary, got {type(stmt).__name__}."
                )
        elif "Effect" in raw_trust_policy or "effect" in raw_trust_policy:
            statements_to_process.append(raw_trust_policy)
        else:
            raise IAMValidationError(
                f"[{context}] Trust policy dictionary must contain 'Statement' or 'Effect'."
            )
    elif isinstance(raw_trust_policy, list):
        statements_to_process = raw_trust_policy
    else:
        raise IAMValidationError(
            f"[{context}] Trust policy must be a dictionary or list, got {type(raw_trust_policy).__name__}."
        )

    relationships: List[Dict[str, Any]] = []
    for idx, stmt in enumerate(statements_to_process):
        if not isinstance(stmt, dict):
            raise IAMValidationError(
                f"[{context}] Trust statement at index {idx} must be a dictionary, got {type(stmt).__name__}."
            )
        stmt_relationships = parse_trust_statement(stmt, target_role=target_role)
        relationships.extend(stmt_relationships)

    return relationships
