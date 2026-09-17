"""IAM Configuration Parser and Normalizer (Phase 1).

Converts synthetic IAM configuration JSON scenarios into standardized, deterministic
representations of entities, permissions, and trust relationships.
"""

from parser.policy_parser import (
    IAMValidationError,
    parse_permission_statement,
    parse_permissions,
)
from parser.trust_parser import (
    parse_trust_statement,
    parse_trust_policy,
)
from parser.normalizer import (
    normalize_scenario,
    normalize_scenario_file,
)

__all__ = [
    "IAMValidationError",
    "parse_permission_statement",
    "parse_permissions",
    "parse_trust_statement",
    "parse_trust_policy",
    "normalize_scenario",
    "normalize_scenario_file",
]
