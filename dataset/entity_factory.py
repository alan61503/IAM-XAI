"""Small, composable builders for synthetic IAM entities and policy statements.

These return plain dictionaries matching the raw scenario schema consumed by
``parser.normalizer.normalize_scenario`` (the same shape as ``data/scenarios/*.json``).
Kept free of any randomness policy decisions -- callers (``scenario_library``)
own *which* entities to create; this module only owns *how* to shape them.
"""

import random
from typing import Any, Dict, List, Optional, Set

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

_ADJECTIVES = ["prod", "dev", "staging", "internal", "partner", "legacy", "core", "shared"]
_NOUNS = ["orders", "payments", "billing", "analytics", "reports", "customers", "inventory", "logs"]

# Resource type -> (read actions, write actions). Every action here is
# classified by graph.action_mapper into CAN_ACCESS (read) or CAN_MODIFY (write).
SERVICE_ACTIONS: Dict[str, Dict[str, List[str]]] = {
    "s3": {"read": ["s3:GetObject", "s3:ListBucket"], "write": ["s3:PutObject", "s3:DeleteObject"]},
    "dynamodb": {"read": ["dynamodb:GetItem", "dynamodb:Query"], "write": ["dynamodb:PutItem", "dynamodb:UpdateItem"]},
    "lambda": {"read": ["lambda:GetFunction"], "write": ["lambda:UpdateFunctionCode"]},
    "ec2": {"read": ["ec2:DescribeInstances"], "write": ["ec2:TerminateInstances"]},
    "secretsmanager": {"read": ["secretsmanager:GetSecretValue"], "write": ["secretsmanager:PutSecretValue"]},
    "kms": {"read": ["kms:DescribeKey"], "write": ["kms:PutKeyPolicy"]},
    "iam_policy": {"read": ["iam:GetPolicy"], "write": ["iam:CreatePolicyVersion"]},
}

# Condition blocks used as mitigating controls, keyed by a short kind name.
CONDITIONS: Dict[str, Dict[str, Any]] = {
    "mfa": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    "source_ip": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    "external_id": {"StringEquals": {"sts:ExternalId": "a1b2c3d4"}},
}


class NameAllocator:
    """Hands out identifiers that are unique within one scenario."""

    def __init__(self, rng: random.Random):
        self._rng = rng
        self._used: Set[str] = set()

    def new(self, prefix: str) -> str:
        while True:
            name = f"{prefix}{self._rng.randint(1000, 9999)}"
            if name not in self._used:
                self._used.add(name)
                return name


def random_account_id(rng: random.Random) -> str:
    """Generate a 12-digit string mimicking a foreign AWS account id."""
    return "".join(str(rng.randint(0, 9)) for _ in range(12))


def user(name: str, permissions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"name": name}
    if permissions:
        entry["permissions"] = permissions
    return entry


def resource(name: str, res_type: str, arn: str) -> Dict[str, Any]:
    return {"name": name, "type": res_type, "arn": arn}


def resource_arn(rng: random.Random, name: str, res_type: str) -> str:
    """Build a realistic ARN for ``res_type``; ``name`` keeps it unique per scenario."""
    slug = f"{rng.choice(_ADJECTIVES)}-{rng.choice(_NOUNS)}-{name.lower()}"
    if res_type == "s3":
        return f"arn:aws:s3:::{slug}"
    if res_type == "dynamodb":
        return f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/{name}"
    if res_type == "lambda":
        return f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{name}"
    if res_type == "ec2":
        return f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/i-{rng.getrandbits(48):012x}"
    if res_type == "secretsmanager":
        return f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{slug}"
    if res_type == "kms":
        return f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/{rng.getrandbits(64):016x}"
    if res_type == "iam_policy":
        return f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}"
    raise ValueError(f"Unknown resource type: {res_type}")


def role_arn(role_name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"


def trust_statement(principal: Any, action: str = "sts:AssumeRole", condition: Optional[str] = None) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        stmt["Condition"] = CONDITIONS[condition]
    return stmt


def trust_policy(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def permission(action: Any, resource_arn: Any, effect: str = "Allow", condition: Optional[str] = None) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": effect, "Action": action, "Resource": resource_arn}
    if condition:
        stmt["Condition"] = CONDITIONS[condition]
    return stmt


def role(
    name: str,
    trust: Optional[Dict[str, Any]] = None,
    permissions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"name": name}
    if trust is not None:
        entry["trust_policy"] = trust
    if permissions is not None:
        entry["permissions"] = permissions
    return entry
