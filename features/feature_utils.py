"""Utility functions for Phase 4 feature extraction.

All helpers are deliberately pure and have no side effects – they receive
plain Python data structures and return deterministic results.
"""

from typing import List, Set, Dict, Any

def is_wildcard_action(action: str) -> bool:
    """Return True if the action string contains a wildcard.

    Wildcards are recognised by the presence of the ``*`` character
    anywhere in the string, e.g. ``*``, ``s3:*``, ``*:Get*``.
    """
    return "*" in action


def is_wildcard_resource(resource: str) -> bool:
    """Return True if the resource string contains a wildcard.

    Typical patterns are ``*``, ``arn:aws:s3:::*`` or ``arn:aws:s3:::bucket/*``.
    """
    return "*" in resource


def service_from_action(action: str) -> str:
    """Extract the AWS service prefix from an action.

    The convention is ``service:Operation``.  If a colon is missing we
    return the whole string (e.g. ``*``) so that it is still counted as a
    distinct service.
    """
    return action.split(":", 1)[0]


def safe_div(numerator: float, denominator: float) -> float:
    """Return ``numerator / denominator`` safely.

    When ``denominator`` is ``0`` the function returns ``0.0`` to avoid
    ``ZeroDivisionError`` and to keep the feature deterministic.
    """
    return 0.0 if denominator == 0 else numerator / denominator


def flatten_conditions(conditions: Dict[str, Any]) -> (Set[str], Set[str]):
    """Return two sets: (operators, keys) found in a condition dict.

    ``conditions`` follows the IAM style where the outer keys are the
    operators (e.g. ``StringEquals``) and the inner dict maps condition
    keys to values.  Both levels are flattened into unique sets.
    """
    operators: Set[str] = set()
    keys: Set[str] = set()
    for op, inner in conditions.items():
        operators.add(op)
        if isinstance(inner, dict):
            keys.update(inner.keys())
        elif isinstance(inner, list):
            # Some conditions may be a list of values – no keys to add.
            continue
    return operators, keys
