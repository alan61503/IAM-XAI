"""Phase 9: Policy Diff & Playbook Generator.

Generates structured JSON diffs and human-readable step-by-step remediation playbooks.
"""

import json
from typing import Any, Dict, List


def generate_policy_diff(original: Dict[str, Any], remediated: Dict[str, Any]) -> Dict[str, Any]:
    """Compare original and remediated scenario dicts to extract policy diffs.

    Returns:
        Structured diff dictionary with entity-level changes.
    """
    diff = {
        "scenario_id": original.get("scenario_id", ""),
        "entities_modified": [],
        "role_trust_policy_diffs": [],
        "permission_policy_diffs": [],
    }

    # Roles diff
    orig_roles = {r.get("name"): r for r in original.get("roles", [])}
    rem_roles = {r.get("name"): r for r in remediated.get("roles", [])}

    for name, o_role in orig_roles.items():
        r_role = rem_roles.get(name)
        if not r_role:
            diff["entities_modified"].append(f"role:{name} (deleted)")
            continue

        # Trust policy diff
        if o_role.get("trust_policy") != r_role.get("trust_policy"):
            diff["entities_modified"].append(f"role:{name} (trust_policy)")
            diff["role_trust_policy_diffs"].append(
                {
                    "role_name": name,
                    "before": o_role.get("trust_policy"),
                    "after": r_role.get("trust_policy"),
                }
            )

        # Permissions diff
        if o_role.get("permissions") != r_role.get("permissions"):
            diff["entities_modified"].append(f"role:{name} (permissions)")
            diff["permission_policy_diffs"].append(
                {
                    "entity_type": "role",
                    "entity_name": name,
                    "before": o_role.get("permissions"),
                    "after": r_role.get("permissions"),
                }
            )

    # Users diff
    orig_users = {u.get("name"): u for u in original.get("users", [])}
    rem_users = {u.get("name"): u for u in remediated.get("users", [])}

    for name, o_user in orig_users.items():
        r_user = rem_users.get(name)
        if not r_user:
            diff["entities_modified"].append(f"user:{name} (deleted)")
            continue

        if o_user.get("permissions") != r_user.get("permissions"):
            diff["entities_modified"].append(f"user:{name} (permissions)")
            diff["permission_policy_diffs"].append(
                {
                    "entity_type": "user",
                    "entity_name": name,
                    "before": o_user.get("permissions"),
                    "after": r_user.get("permissions"),
                }
            )

    return diff


def generate_remediation_playbook(
    choke_point: Dict[str, Any],
    summary: Dict[str, Any],
    verification: Dict[str, Any],
) -> str:
    """Generate a markdown formatted step-by-step remediation playbook."""
    lines = [
        f"# IAM Security Remediation Playbook — Choke Point `{choke_point.get('choke_point_id', 'CP')}`",
        "",
        "## Executive Summary",
        f"- **Source Node**: `{choke_point.get('source')}`",
        f"- **Target Node**: `{choke_point.get('target')}`",
        f"- **Edge Type**: `{choke_point.get('edge_type')}`",
        f"- **Risk Impact**: Severing this choke point blocks **{choke_point.get('paths_blocked', 1)}** attack path(s).",
        f"- **Verification Status**: `{verification.get('status', 'PENDING')}` ({verification.get('eliminated_paths_count', 0)} paths eliminated).",
        "",
        "## Recommended Actions",
        f"1. **Target Entity**: `{summary.get('target_entity')}`",
        f"2. **Patch Applied**: `{summary.get('patch_type')}`",
        f"3. **Description**: {summary.get('description')}",
        "",
        "## Step-by-Step Remediation Guide",
        "1. **Access AWS IAM Console / Terraform**: Locate the identity configuration for the affected principal.",
        "2. **Review Policy Statements**: Identify policy statements containing broad actions or trust permissions.",
        "3. **Apply Patch**: Update JSON policy definition to restrict actions or add security conditions (e.g., MFA requirement).",
        "4. **Re-Verify Attack Graph**: Run IAM-XAI path verification engine to confirm zero active attack paths remain.",
        "",
        "---",
        "*Generated automatically by IAM-XAI Remediation Engine*",
    ]
    return "\n".join(lines)
