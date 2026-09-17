"""Main normalization module converting synthetic IAM configurations to standard representation."""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from parser.policy_parser import (
    IAMValidationError,
    parse_permissions,
)
from parser.trust_parser import (
    parse_trust_policy,
)


def _validate_entity_name(name: Any, entity_type: str, index: int) -> str:
    """Validate that an entity has a valid, non-empty string name."""
    if not isinstance(name, str) or not name.strip():
        raise IAMValidationError(
            f"Entity '{entity_type}' at index {index} must have a non-empty string 'name'."
        )
    return name.strip()


def normalize_scenario(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a synthetic IAM scenario dictionary into the canonical format.

    Args:
        data: Raw synthetic IAM scenario dictionary.

    Returns:
        Canonical normalized dictionary:
        {
            "scenario_id": str,
            "entities": [...],
            "permissions": [...],
            "trust_relationships": [...]
        }
    """
    if not isinstance(data, dict):
        raise IAMValidationError(
            f"Scenario data must be a JSON object (dict), got {type(data).__name__}."
        )

    # 1. Validate scenario_id
    scenario_id = data.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise IAMValidationError("Missing or invalid required field 'scenario_id'. Must be a non-empty string.")
    scenario_id = scenario_id.strip()

    entities: List[Dict[str, Any]] = []
    permissions: List[Dict[str, Any]] = []
    trust_relationships: List[Dict[str, Any]] = []

    # 2. Extract Users
    users = data.get("users", [])
    if not isinstance(users, list):
        raise IAMValidationError(f"'users' must be a list, got {type(users).__name__}.")

    for idx, user in enumerate(users):
        if not isinstance(user, dict):
            raise IAMValidationError(f"User at index {idx} must be a dictionary, got {type(user).__name__}.")
        user_name = _validate_entity_name(user.get("name"), "user", idx)
        user_entity = {
            "type": "user",
            "name": user_name,
        }
        entities.append(user_entity)

        # In case user has inline permissions
        if "permissions" in user:
            user_perms = parse_permissions(user["permissions"], source=user_name)
            permissions.extend(user_perms)

    # 3. Extract Groups (if present)
    groups = data.get("groups", [])
    if not isinstance(groups, list):
        raise IAMValidationError(f"'groups' must be a list, got {type(groups).__name__}.")

    for idx, group in enumerate(groups):
        if not isinstance(group, dict):
            raise IAMValidationError(f"Group at index {idx} must be a dictionary, got {type(group).__name__}.")
        group_name = _validate_entity_name(group.get("name"), "group", idx)
        group_entity = {
            "type": "group",
            "name": group_name,
        }
        entities.append(group_entity)

        if "permissions" in group:
            group_perms = parse_permissions(group["permissions"], source=group_name)
            permissions.extend(group_perms)

    # 4. Extract Roles, their trust policies, and permissions
    roles = data.get("roles", [])
    if not isinstance(roles, list):
        raise IAMValidationError(f"'roles' must be a list, got {type(roles).__name__}.")

    for idx, role in enumerate(roles):
        if not isinstance(role, dict):
            raise IAMValidationError(f"Role at index {idx} must be a dictionary, got {type(role).__name__}.")
        role_name = _validate_entity_name(role.get("name"), "role", idx)
        role_entity = {
            "type": "role",
            "name": role_name,
        }
        entities.append(role_entity)

        # Parse trust policy
        if "trust_policy" in role:
            role_trust = parse_trust_policy(role["trust_policy"], target_role=role_name)
            trust_relationships.extend(role_trust)

        # Parse permissions
        if "permissions" in role:
            role_perms = parse_permissions(role["permissions"], source=role_name)
            permissions.extend(role_perms)

    # 5. Extract Resources
    resources = data.get("resources", [])
    if not isinstance(resources, list):
        raise IAMValidationError(f"'resources' must be a list, got {type(resources).__name__}.")

    for idx, resource in enumerate(resources):
        if not isinstance(resource, dict):
            raise IAMValidationError(f"Resource at index {idx} must be a dictionary, got {type(resource).__name__}.")
        res_name = _validate_entity_name(resource.get("name"), "resource", idx)
        res_entity: Dict[str, Any] = {
            "type": "resource",
            "name": res_name,
        }
        if "arn" in resource and isinstance(resource["arn"], str):
            res_entity["arn"] = resource["arn"].strip()
        if "type" in resource and isinstance(resource["type"], str):
            res_entity["resource_type"] = resource["type"].strip()

        entities.append(res_entity)

    # Return canonical normalized schema
    return {
        "scenario_id": scenario_id,
        "entities": entities,
        "permissions": permissions,
        "trust_relationships": trust_relationships,
    }


def normalize_scenario_file(filepath: Union[str, Path]) -> Dict[str, Any]:
    """Load, parse, and normalize a synthetic IAM scenario JSON file.

    Args:
        filepath: Path to the JSON scenario file.

    Returns:
        Canonical normalized dictionary.

    Raises:
        IAMValidationError: If file does not exist, contains invalid JSON, or fails validation.
    """
    path = Path(filepath)
    if not path.exists():
        raise IAMValidationError(f"Scenario file not found: {path}")
    if not path.is_file():
        raise IAMValidationError(f"Scenario path is not a file: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise IAMValidationError(f"Invalid JSON syntax in '{path}': {e}") from e
    except Exception as e:
        raise IAMValidationError(f"Error reading scenario file '{path}': {e}") from e

    return normalize_scenario(data)
