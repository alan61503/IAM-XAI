"""Small, composable builders for synthetic IAM entities and policy statements.

These return plain dictionaries matching the raw scenario schema consumed by
``parser.normalizer.normalize_scenario`` (the same shape as ``data/scenarios/*.json``).
Kept free of any randomness policy decisions -- callers (``scenario_library``)
own *which* entities to create; this module only owns *how* to shape them.
"""

import random
from typing import Any, Dict, List, Optional

_ADJECTIVES = ["prod", "dev", "staging", "internal", "partner", "legacy", "core", "shared"]
_NOUNS = ["orders", "payments", "billing", "analytics", "reports", "customers", "inventory", "logs"]


def random_name(rng: random.Random, prefix: str) -> str:
    """Generate a short, unique-enough identifier for use within one scenario."""
    return f"{prefix}{rng.randint(1000, 9999)}"


def random_account_id(rng: random.Random) -> str:
    """Generate a 12-digit string mimicking a foreign AWS account id."""
    return "".join(str(rng.randint(0, 9)) for _ in range(12))


def user(name: str) -> Dict[str, Any]:
    return {"name": name}


def resource(name: str, res_type: str, arn: str) -> Dict[str, Any]:
    return {"name": name, "type": res_type, "arn": arn}


def s3_resource(rng: random.Random, name: str) -> Dict[str, Any]:
    bucket = f"{rng.choice(_ADJECTIVES)}-{rng.choice(_NOUNS)}-{rng.randint(100, 999)}"
    return resource(name, "s3", f"arn:aws:s3:::{bucket}")


def secret_resource(rng: random.Random, name: str) -> Dict[str, Any]:
    secret = f"{rng.choice(_ADJECTIVES)}/{rng.choice(_NOUNS)}-secret"
    return resource(name, "secretsmanager", f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{secret}")


def iam_policy_resource(rng: random.Random, name: str) -> Dict[str, Any]:
    policy = f"{rng.choice(_ADJECTIVES).capitalize()}Policy{rng.randint(100, 999)}"
    return resource(name, "iam_policy", f"arn:aws:iam::123456789012:policy/{policy}")


def trust_statement(principal: Any, action: str = "sts:AssumeRole") -> Dict[str, Any]:
    return {"Effect": "Allow", "Principal": principal, "Action": action}


def trust_policy(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def permission(action: Any, resource_arn: Any, effect: str = "Allow") -> Dict[str, Any]:
    return {"Effect": effect, "Action": action, "Resource": resource_arn}


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
