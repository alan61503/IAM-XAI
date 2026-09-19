"""Attack scenario templates from CLAUDE.md section 5.3.

Each ``build_*`` function takes a seeded ``random.Random`` and a scenario id
and returns ``(raw_scenario, meta)``:

- ``raw_scenario`` is a dict shaped like ``data/scenarios/*.json``, ready for
  ``parser.normalizer.normalize_scenario``.
- ``meta`` records what the generator can't infer from the graph alone:
  ``sensitive_resources`` (resource/role names to mark sensitive) and
  ``pass_role_targets`` (role names that should also be probed as explicit
  path targets, since ``iam:PassRole`` alone never satisfies the default
  auto-discovered resource targets -- see ``dataset/generator.py``).

``REGISTRY`` maps scenario type -> (builder, weight). Weights are chosen so
that the four risk labels come out roughly balanced across a large run.
"""

import random
from typing import Any, Dict, Tuple

from . import entity_factory as ef

Scenario = Tuple[Dict[str, Any], Dict[str, Any]]


def build_read_only(rng: random.Random, scenario_id: str) -> Scenario:
    """Single user, single role, read-only access to one exact object. LOW.

    Deliberately avoids any ``*`` in the resource pattern -- a bucket/object
    wildcard suffix (``bucket/*``) already counts as ``wildcard_resource`` in
    Phase 4's feature extractor, which would misclassify this as MEDIUM.
    """
    u = ef.random_name(rng, "User")
    r = ef.random_name(rng, "Role")
    bucket = ef.random_name(rng, "Bucket")

    bucket_res = ef.s3_resource(rng, bucket)
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": u})),
                permissions=[ef.permission("s3:GetObject", bucket_res["arn"] + "/status.json")],
            )
        ],
        "resources": [bucket_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_wildcard_s3(rng: random.Random, scenario_id: str) -> Scenario:
    """Wildcard S3 action against an ordinary bucket. MEDIUM."""
    u = ef.random_name(rng, "User")
    r = ef.random_name(rng, "Role")
    bucket = ef.random_name(rng, "Bucket")

    bucket_res = ef.s3_resource(rng, bucket)
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": u})),
                permissions=[ef.permission("s3:*", bucket_res["arn"] + "/*")],
            )
        ],
        "resources": [bucket_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_pass_role_escalation(rng: random.Random, scenario_id: str) -> Scenario:
    """User assumes a role that can PassRole into a privileged role. HIGH."""
    u = ef.random_name(rng, "User")
    r = ef.random_name(rng, "Role")
    target_role = ef.random_name(rng, "AdminRole")

    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": u})),
                permissions=[
                    ef.permission("iam:PassRole", f"arn:aws:iam::123456789012:role/{target_role}")
                ],
            ),
            ef.role(target_role),
        ],
        "resources": [],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": [target_role]}


def build_assume_role_chain(rng: random.Random, scenario_id: str) -> Scenario:
    """User -> RoleA -> RoleB -> resource, a two-hop role chain. HIGH."""
    u = ef.random_name(rng, "User")
    role_a = ef.random_name(rng, "RoleA")
    role_b = ef.random_name(rng, "RoleB")
    table = ef.random_name(rng, "Table")

    table_res = ef.resource(table, "dynamodb", f"arn:aws:dynamodb:us-east-1:123456789012:table/{table}")
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(role_a, trust=ef.trust_policy(ef.trust_statement({"AWS": u}))),
            ef.role(
                role_b,
                trust=ef.trust_policy(ef.trust_statement({"AWS": role_a})),
                permissions=[ef.permission("dynamodb:GetItem", table_res["arn"])],
            ),
        ],
        "resources": [table_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_long_chain(rng: random.Random, scenario_id: str) -> Scenario:
    """User -> RoleA -> RoleB -> RoleC -> resource, a three-hop role chain. HIGH."""
    u = ef.random_name(rng, "User")
    role_a = ef.random_name(rng, "RoleA")
    role_b = ef.random_name(rng, "RoleB")
    role_c = ef.random_name(rng, "RoleC")
    bucket = ef.random_name(rng, "Bucket")

    bucket_res = ef.s3_resource(rng, bucket)
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(role_a, trust=ef.trust_policy(ef.trust_statement({"AWS": u}))),
            ef.role(role_b, trust=ef.trust_policy(ef.trust_statement({"AWS": role_a}))),
            ef.role(
                role_c,
                trust=ef.trust_policy(ef.trust_statement({"AWS": role_b})),
                permissions=[ef.permission("s3:GetObject", bucket_res["arn"] + "/*")],
            ),
        ],
        "resources": [bucket_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_external_trust_critical(rng: random.Random, scenario_id: str) -> Scenario:
    """A role trusts an undeclared (external) principal and exposes a secret. CRITICAL."""
    external_principal = ef.random_name(rng, "partner-")
    r = ef.random_name(rng, "Role")
    secret = ef.random_name(rng, "Secret")

    secret_res = ef.secret_resource(rng, secret)
    scenario = {
        "scenario_id": scenario_id,
        "users": [],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": external_principal})),
                permissions=[ef.permission("secretsmanager:GetSecretValue", secret_res["arn"])],
            )
        ],
        "resources": [secret_res],
    }
    return scenario, {"sensitive_resources": [secret], "pass_role_targets": []}


def build_policy_modification(rng: random.Random, scenario_id: str) -> Scenario:
    """User assumes a role that can rewrite IAM policy. CRITICAL."""
    u = ef.random_name(rng, "User")
    r = ef.random_name(rng, "Role")
    policy = ef.random_name(rng, "Policy")

    policy_res = ef.iam_policy_resource(rng, policy)
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": u})),
                permissions=[ef.permission("iam:PutRolePolicy", policy_res["arn"])],
            )
        ],
        "resources": [policy_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_cross_account_wildcard(rng: random.Random, scenario_id: str) -> Scenario:
    """A role trusts a raw foreign AWS account id and grants wildcard S3 access. CRITICAL."""
    account_id = ef.random_account_id(rng)
    r = ef.random_name(rng, "Role")
    bucket = ef.random_name(rng, "Bucket")

    bucket_res = ef.s3_resource(rng, bucket)
    scenario = {
        "scenario_id": scenario_id,
        "users": [],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": account_id})),
                permissions=[ef.permission("s3:*", bucket_res["arn"] + "/*")],
            )
        ],
        "resources": [bucket_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


def build_admin_wildcard(rng: random.Random, scenario_id: str) -> Scenario:
    """User assumes a role holding the global '*' action -- IAM-admin-equivalent. CRITICAL."""
    u = ef.random_name(rng, "User")
    r = ef.random_name(rng, "Role")
    bucket = ef.random_name(rng, "Bucket")

    bucket_res = ef.s3_resource(rng, bucket)
    scenario = {
        "scenario_id": scenario_id,
        "users": [ef.user(u)],
        "roles": [
            ef.role(
                r,
                trust=ef.trust_policy(ef.trust_statement({"AWS": u})),
                permissions=[ef.permission("*", "*")],
            )
        ],
        "resources": [bucket_res],
    }
    return scenario, {"sensitive_resources": [], "pass_role_targets": []}


# scenario_type -> (builder, relative weight). Weight groups sum to 4 per risk
# label (LOW=4, MEDIUM=4, HIGH=2+1+1=4, CRITICAL=1*4=4) for a roughly even split.
REGISTRY = {
    "read_only": (build_read_only, 4),
    "wildcard_s3": (build_wildcard_s3, 4),
    "pass_role_escalation": (build_pass_role_escalation, 2),
    "assume_role_chain": (build_assume_role_chain, 1),
    "long_chain": (build_long_chain, 1),
    "external_trust_critical": (build_external_trust_critical, 1),
    "policy_modification": (build_policy_modification, 1),
    "cross_account_wildcard": (build_cross_account_wildcard, 1),
    "admin_wildcard": (build_admin_wildcard, 1),
}
