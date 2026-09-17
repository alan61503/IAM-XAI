"""Policy statement parsing and normalization for IAM permissions."""

from typing import Any, Dict, List, Union


class IAMValidationError(ValueError):
    """Raised when an IAM configuration or policy is invalid or malformed."""
    pass


def _normalize_string_or_list(
    val: Any, field_name: str, context: str = ""
) -> List[str]:
    """Normalize a string or list of strings to a list of strings.

    Preserves exact string contents (e.g., wildcards).
    Raises IAMValidationError if value is empty, invalid type, or contains non-strings.
    """
    ctx_prefix = f"[{context}] " if context else ""
    if val is None:
        raise IAMValidationError(f"{ctx_prefix}Field '{field_name}' is required but was None or missing.")

    if isinstance(val, str):
        val = val.strip()
        if not val:
            raise IAMValidationError(f"{ctx_prefix}Field '{field_name}' cannot be an empty string.")
        return [val]

    if isinstance(val, list):
        if len(val) == 0:
            raise IAMValidationError(f"{ctx_prefix}Field '{field_name}' cannot be an empty list.")
        normalized = []
        for idx, item in enumerate(val):
            if not isinstance(item, str):
                raise IAMValidationError(
                    f"{ctx_prefix}Field '{field_name}' item at index {idx} must be a string, got {type(item).__name__}."
                )
            item_str = item.strip()
            if not item_str:
                raise IAMValidationError(
                    f"{ctx_prefix}Field '{field_name}' item at index {idx} cannot be an empty string."
                )
            normalized.append(item_str)
        return normalized

    raise IAMValidationError(
        f"{ctx_prefix}Field '{field_name}' must be a string or list of strings, got {type(val).__name__}."
    )


def _validate_effect(effect: Any, context: str = "") -> str:
    """Validate that effect is 'Allow' or 'Deny'."""
    ctx_prefix = f"[{context}] " if context else ""
    if not isinstance(effect, str):
        raise IAMValidationError(
            f"{ctx_prefix}Field 'Effect' must be a string ('Allow' or 'Deny'), got {type(effect).__name__}."
        )

    effect_clean = effect.strip()
    if effect_clean.lower() == "allow":
        return "Allow"
    elif effect_clean.lower() == "deny":
        return "Deny"
    else:
        raise IAMValidationError(
            f"{ctx_prefix}Invalid Effect: '{effect}'. Expected 'Allow' or 'Deny'."
        )


def _extract_conditions(statement: Dict[str, Any], context: str = "") -> Dict[str, Any]:
    """Extract and validate conditions block from statement."""
    ctx_prefix = f"[{context}] " if context else ""
    # Check both 'Condition' (AWS standard) and 'conditions' (internal format)
    cond = statement.get("Condition")
    if cond is None:
        cond = statement.get("conditions")

    if cond is None:
        return {}

    if not isinstance(cond, dict):
        raise IAMValidationError(
            f"{ctx_prefix}'Condition' block must be a JSON object (dict), got {type(cond).__name__}."
        )

    return cond


def parse_permission_statement(
    statement: Dict[str, Any], source: str = ""
) -> Dict[str, Any]:
    """Parse a single IAM permission statement into standard representation.

    Args:
        statement: Dictionary representing an IAM statement.
        source: Name of the entity (e.g. role name) holding the permission.

    Returns:
        Standardized permission dictionary:
        {
            "source": source,
            "effect": "Allow" | "Deny",
            "actions": ["..."],
            "resources": ["..."],
            "conditions": {...}
        }
    """
    context = f"source: {source}" if source else "permission statement"

    if not isinstance(statement, dict):
        raise IAMValidationError(
            f"Permission statement must be a dictionary, got {type(statement).__name__}."
        )

    # Validate and normalize Effect
    if "Effect" not in statement and "effect" not in statement:
        raise IAMValidationError(f"[{context}] Missing required 'Effect' in permission statement.")
    raw_effect = statement.get("Effect") if "Effect" in statement else statement.get("effect")
    effect = _validate_effect(raw_effect, context=context)

    # Validate and normalize Action
    raw_action = None
    if "Action" in statement:
        raw_action = statement.get("Action")
    elif "action" in statement:
        raw_action = statement.get("action")
    elif "actions" in statement:
        raw_action = statement.get("actions")
    else:
        raise IAMValidationError(f"[{context}] Missing required 'Action' in permission statement.")
    actions = _normalize_string_or_list(raw_action, "Action", context=context)

    # Validate and normalize Resource
    raw_resource = None
    if "Resource" in statement:
        raw_resource = statement.get("Resource")
    elif "resource" in statement:
        raw_resource = statement.get("resource")
    elif "resources" in statement:
        raw_resource = statement.get("resources")
    else:
        raise IAMValidationError(f"[{context}] Missing required 'Resource' in permission statement.")
    resources = _normalize_string_or_list(raw_resource, "Resource", context=context)

    # Extract conditions
    conditions = _extract_conditions(statement, context=context)

    return {
        "source": source,
        "effect": effect,
        "actions": actions,
        "resources": resources,
        "conditions": conditions,
    }


def parse_permissions(
    raw_permissions: Union[List[Any], Dict[str, Any]], source: str = ""
) -> List[Dict[str, Any]]:
    """Parse permissions configuration for an entity.

    Can accept:
    - A list of permission statement dicts
    - A single statement dict
    - A policy document dict with 'Statement' key (which can be a list or a single dict)

    Args:
        raw_permissions: Raw permission data structure.
        source: Name of the entity associated with these permissions.

    Returns:
        List of normalized permission dictionaries.
    """
    if raw_permissions is None:
        return []

    statements_to_process: List[Dict[str, Any]] = []

    if isinstance(raw_permissions, dict):
        if "Statement" in raw_permissions:
            stmt = raw_permissions["Statement"]
            if isinstance(stmt, list):
                statements_to_process.extend(stmt)
            elif isinstance(stmt, dict):
                statements_to_process.append(stmt)
            else:
                raise IAMValidationError(
                    f"['{source}'] 'Statement' in policy must be a list or dictionary, got {type(stmt).__name__}."
                )
        elif "Effect" in raw_permissions or "effect" in raw_permissions:
            statements_to_process.append(raw_permissions)
        else:
            raise IAMValidationError(
                f"['{source}'] Permission dictionary must contain either 'Statement' or 'Effect'."
            )
    elif isinstance(raw_permissions, list):
        statements_to_process = raw_permissions
    else:
        raise IAMValidationError(
            f"['{source}'] Permissions must be a list or dictionary, got {type(raw_permissions).__name__}."
        )

    parsed_list = []
    for idx, stmt in enumerate(statements_to_process):
        if not isinstance(stmt, dict):
            raise IAMValidationError(
                f"['{source}'] Permission statement at index {idx} must be a dictionary, got {type(stmt).__name__}."
            )
        parsed = parse_permission_statement(stmt, source=source)
        parsed_list.append(parsed)

    return parsed_list
