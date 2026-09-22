"""Column ordering and label vocabulary for the Phase 5 dataset export.

Mirrors ``features/feature_schema.py``'s role for Phase 4: a single place
that fixes the deterministic output shape described in CLAUDE.md section 5.1.
The model's feature groups are defined here too, so the generator, the
preprocessing pipeline and the dashboard all agree on them.
"""

DATASET_SCHEMA_VERSION = "2.0"

IDENTIFIER_COLUMNS = ["scenario_id", "path_id", "source_identity", "target_resource"]

NUMERIC_FEATURES = [
    "path_length",
    "role_count",
    "user_count",
    "resource_count",
    "action_count",
    "wildcard_action_count",
    "wildcard_resource_count",
    "broad_permission_edge_count",
    "conditional_edge_count",
    "condition_key_count",
    "distinct_service_count",
    "classification_tag",
]

BINARY_FEATURES = [
    "assume_role",
    "pass_role",
    "wildcard_action",
    "wildcard_resource",
    "policy_modification",
    "external_trust",
    "cross_account",
    "wildcard_principal",
    "sensitive_target",
    "admin_permission",
    "write_access",
    "has_conditions",
    "target_privileged",
]

CATEGORICAL_FEATURES = ["target_type", "target_service"]

FEATURE_COLUMNS = NUMERIC_FEATURES + BINARY_FEATURES + CATEGORICAL_FEATURES

# Ground truth and analysis metadata -- never model inputs.
LABEL_COLUMNS = ["risk_label", "risk_score", "attack_type", "risk_cause"]
METADATA_COLUMNS = ["scenario_patterns", "target_classification"]

DATASET_COLUMNS = IDENTIFIER_COLUMNS + FEATURE_COLUMNS + LABEL_COLUMNS + METADATA_COLUMNS

RISK_LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

ATTACK_TYPES = ("Privilege Escalation", "Lateral Movement", "Data Access")
