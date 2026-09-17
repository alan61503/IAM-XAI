"""Feature schema for Phase 4.

Defines the version string and a canonical ordering of feature names.
Used by the serializer to guarantee deterministic column order.
"""

FEATURE_SCHEMA_VERSION = "1.0"

# Ordered list of feature names as they will appear in JSON/CSV records.
FEATURE_NAMES = [
    # Path structure
    "hop_count",
    "node_count",
    "unique_node_count",
    "user_count",
    "role_count",
    "resource_count",
    # Edge‑type counts
    "assume_count",
    "access_count",
    "modify_count",
    "passrole_count",
    "unique_edge_type_count",
    "has_assume",
    "has_access",
    "has_modify",
    "has_passrole",
    # Permission breadth
    "action_count",
    "unique_action_count",
    "resource_pattern_count",
    "unique_resource_pattern_count",
    "wildcard_action_count",
    "wildcard_resource_count",
    "has_wildcard_action",
    "has_wildcard_resource",
    # Broad permission indicators
    "broad_permission_edge_count",
    "has_broad_permission",
    # Trust / principal features
    "trust_edge_count",  # defined as number of CAN_ASSUME edges only
    "external_principal_count",
    "service_principal_count",
    "wildcard_principal_count",
    "has_external_principal",
    "has_service_principal",
    "has_wildcard_principal",
    # Condition features
    "conditional_edge_count",
    "has_conditions",
    "condition_operator_count",
    "condition_key_count",
    # Effect features
    "allow_edge_count",
    "deny_edge_count",
    # Target features
    "target_type",
    "target_is_resource",
    "target_is_role",
    "target_is_user",
    # Optional target metadata – include only if present in the path
    "target_sensitive",
    "target_criticality",
    # Path composition ratios
    "role_hop_ratio",
    "assume_ratio",
    "access_ratio",
    "modify_ratio",
    "passrole_ratio",
    "permission_edge_count",
      # duplicate removed, keep only one definition above
    # Complexity
    "distinct_service_count",
]
