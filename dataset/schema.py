"""Column ordering and label vocabulary for the Phase 5 dataset export.

Mirrors ``features/feature_schema.py``'s role for Phase 4: a single place
that fixes the deterministic output shape described in CLAUDE.md section 5.1.
"""

DATASET_SCHEMA_VERSION = "1.0"

DATASET_COLUMNS = [
    "scenario_id",
    "path_id",
    "source_identity",
    "target_resource",
    "path_length",
    "role_count",
    "user_count",
    "assume_role",
    "pass_role",
    "wildcard_action",
    "wildcard_resource",
    "policy_modification",
    "external_trust",
    "cross_account",
    "sensitive_target",
    "admin_permission",
    "risk_label",
    "risk_score",
    "attack_type",
    "risk_cause",
]

RISK_LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

ATTACK_TYPES = ("Privilege Escalation", "Lateral Movement", "Data Access")
