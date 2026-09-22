"""Synthetic IAM environments with injected attack patterns (CLAUDE.md section 5.2-5.3).

``build_environment`` creates one randomized environment: a benign baseline
(users, roles, resources and ordinary least-privilege access -- including
occasional explicit Deny guardrails -- sized per the CLAUDE.md 5.2 ranges) into which zero or more attack patterns from
``PATTERNS`` are injected. Each environment therefore yields many overlapping
attack paths of mixed risk, instead of a single path per fixed template.

It returns ``(raw_scenario, meta)``:

- ``raw_scenario`` is a dict shaped like ``data/scenarios/*.json``, ready for
  ``parser.normalizer.normalize_scenario``. Resources an operator has *tagged*
  with a DataClassification carry ``"tags": {"DataClassification": ...}``
  (and ``"sensitive": true`` when confidential or restricted) -- the only
  classification signal a real analyzer would see.
- ``meta`` holds generator-side ground truth the model never sees directly:
  the true data classification tier of every resource (tagging is deliberately
  imperfect), which roles are privileged, which roles are PassRole targets,
  and which patterns were injected.
"""

import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import entity_factory as ef

Scenario = Tuple[Dict[str, Any], Dict[str, Any]]

# CLAUDE.md 5.2 entity ranges.
USER_RANGE = (3, 20)
ROLE_RANGE = (2, 15)
RESOURCE_RANGE = (5, 30)

# Data classification tiers: 0=public, 1=internal, 2=confidential, 3=restricted.
TIER_NAMES = ("public", "internal", "confidential", "restricted")
SENSITIVE_TIER = 2

RESOURCE_TYPE_WEIGHTS = {"s3": 5, "dynamodb": 3, "lambda": 2, "ec2": 2, "secretsmanager": 2, "kms": 1}

# Resource type -> probability of each classification tier.
TIER_WEIGHTS = {
    "s3": (0.30, 0.35, 0.25, 0.10),
    "dynamodb": (0.10, 0.35, 0.35, 0.20),
    "lambda": (0.30, 0.50, 0.15, 0.05),
    "ec2": (0.20, 0.50, 0.25, 0.05),
    "secretsmanager": (0.00, 0.10, 0.40, 0.50),
    "kms": (0.00, 0.10, 0.40, 0.50),
    "iam_policy": (0.00, 0.00, 0.30, 0.70),
}

# DataClassification tagging is imperfect: some resources are untagged and a
# few carry a tag one tier off from their true classification.
TAG_RECALL = 0.85
TAG_ERROR = 0.05

# Fraction of baseline roles carrying an explicit Deny guardrail.
GUARDRAIL_RATE = 0.15

# ARN segment preceding the resource id, used to build service-wide wildcards.
_WILDCARD_ARN = {
    "s3": "arn:aws:s3:::*",
    "dynamodb": f"arn:aws:dynamodb:{ef.REGION}:{ef.ACCOUNT_ID}:table/*",
    "lambda": f"arn:aws:lambda:{ef.REGION}:{ef.ACCOUNT_ID}:function:*",
    "ec2": f"arn:aws:ec2:{ef.REGION}:{ef.ACCOUNT_ID}:instance/*",
    "secretsmanager": f"arn:aws:secretsmanager:{ef.REGION}:{ef.ACCOUNT_ID}:secret:*",
    "kms": f"arn:aws:kms:{ef.REGION}:{ef.ACCOUNT_ID}:key/*",
}


@dataclass
class Environment:
    """Mutable builder state for one synthetic environment."""

    rng: random.Random
    scenario_id: str
    names: ef.NameAllocator
    users: List[Dict[str, Any]] = field(default_factory=list)
    roles: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    resource_tiers: Dict[str, int] = field(default_factory=dict)
    resource_types: Dict[str, str] = field(default_factory=dict)
    privileged_roles: Set[str] = field(default_factory=set)
    pass_role_targets: Set[str] = field(default_factory=set)
    patterns: List[str] = field(default_factory=list)

    # -- entity helpers ---------------------------------------------------

    def add_resource(self, res_type: str, tier: Optional[int] = None) -> Dict[str, Any]:
        name = self.names.new(res_type.capitalize().replace("_", ""))
        res = ef.resource(name, res_type, ef.resource_arn(self.rng, name, res_type))
        if tier is None:
            tier = self.rng.choices(range(4), weights=TIER_WEIGHTS[res_type], k=1)[0]
        if self.rng.random() < TAG_RECALL:
            tag_tier = tier
            if self.rng.random() < TAG_ERROR:
                tag_tier = min(3, tier + 1) if tier == 0 or (tier < 3 and self.rng.random() < 0.5) else tier - 1
            res["tags"] = {"DataClassification": TIER_NAMES[tag_tier]}
            if tag_tier >= SENSITIVE_TIER:
                res["sensitive"] = True
        self.resources.append(res)
        self.resource_tiers[name] = tier
        self.resource_types[name] = res_type
        return res

    def random_resource(self, types: Optional[List[str]] = None) -> Dict[str, Any]:
        pool = [r for r in self.resources if types is None or r["type"] in types]
        return self.rng.choice(pool) if pool else self.add_resource(self.rng.choice(types or ["s3"]))

    def add_role(self, trust: Optional[Dict[str, Any]], permissions: List[Dict[str, Any]], prefix: str = "Role") -> Dict[str, Any]:
        entry = ef.role(self.names.new(prefix), trust=trust, permissions=permissions)
        self.roles.append(entry)
        return entry

    def random_user_name(self) -> str:
        return self.rng.choice(self.users)["name"]

    def reachable_roles(self) -> List[Dict[str, Any]]:
        """Roles with a trust policy (i.e. that some identity can assume)."""
        return [r for r in self.roles if "trust_policy" in r and r["name"] not in self.privileged_roles]

    def access_statement(self, res: Dict[str, Any], write: bool, condition: Optional[str] = None) -> Dict[str, Any]:
        actions = ef.SERVICE_ACTIONS[res["type"]]["write" if write else "read"]
        chosen = self.rng.sample(actions, k=self.rng.randint(1, len(actions)))
        target = res["arn"]
        if res["type"] == "s3" and self.rng.random() < 0.5:
            target = f"{res['arn']}/*"
        return ef.permission(chosen if len(chosen) > 1 else chosen[0], target, condition=condition)

    def maybe_condition(self, kind: str, probability: float) -> Optional[str]:
        return kind if self.rng.random() < probability else None


# -- baseline ---------------------------------------------------------------


def _build_baseline(env: Environment) -> None:
    rng = env.rng
    for _ in range(rng.randint(*RESOURCE_RANGE)):
        res_type = rng.choices(list(RESOURCE_TYPE_WEIGHTS), weights=list(RESOURCE_TYPE_WEIGHTS.values()), k=1)[0]
        env.add_resource(res_type)

    for _ in range(rng.randint(*USER_RANGE)):
        env.users.append(ef.user(env.names.new("User")))

    for idx in range(rng.randint(*ROLE_RANGE)):
        principals = rng.sample([u["name"] for u in env.users], k=min(len(env.users), rng.randint(1, 2)))
        if idx > 0 and rng.random() < 0.25:
            principals[0] = rng.choice(env.roles)["name"]  # benign role-to-role delegation
        trust = ef.trust_policy(
            ef.trust_statement({"AWS": principals if len(principals) > 1 else principals[0]}, condition=env.maybe_condition("mfa", 0.15))
        )
        statements = [
            env.access_statement(env.random_resource(), write=rng.random() < 0.2, condition=env.maybe_condition("source_ip", 0.1))
            for _ in range(rng.randint(1, 3))
        ]
        env.add_role(trust, statements)

    for u in env.users:
        if rng.random() < 0.3:
            u["permissions"] = [env.access_statement(env.random_resource(), write=False)]

    for r in env.roles:
        if rng.random() < GUARDRAIL_RATE:
            _add_deny_guardrail(env, r)


def _add_deny_guardrail(env: Environment, role: Dict[str, Any]) -> None:
    """Explicit Deny on one resource the role can reach: all actions, or writes only."""
    stmt = env.rng.choice([s for s in role["permissions"] if s["Effect"] == "Allow"])
    arn = stmt["Resource"][:-2] if stmt["Resource"].endswith("/*") else stmt["Resource"]
    res_type = next(r["type"] for r in env.resources if r["arn"] == arn)
    actions = "*" if env.rng.random() < 0.4 else ef.SERVICE_ACTIONS[res_type]["write"]
    resources = [arn, f"{arn}/*"] if res_type == "s3" else arn
    role["permissions"].append(ef.permission(actions, resources, effect="Deny"))


# -- attack patterns (CLAUDE.md 5.3) ------------------------------------------


def inject_wildcard_action(env: Environment) -> None:
    """A reachable role gets ``service:*`` on one resource."""
    res = env.random_resource(list(RESOURCE_TYPE_WEIGHTS))
    target = f"{res['arn']}/*" if res["type"] == "s3" else res["arn"]
    env.rng.choice(env.reachable_roles())["permissions"].append(ef.permission(f"{res['type']}:*", target))


def inject_wildcard_resource(env: Environment) -> None:
    """A reachable role gets read access to every resource of one service."""
    res_type = env.rng.choice([r["type"] for r in env.resources if r["type"] in _WILDCARD_ARN])
    action = env.rng.choice(ef.SERVICE_ACTIONS[res_type]["read"])
    env.rng.choice(env.reachable_roles())["permissions"].append(ef.permission(action, _WILDCARD_ARN[res_type]))


def inject_pass_role(env: Environment) -> None:
    """A reachable role can iam:PassRole a service role -- privileged or not."""
    privileged = env.rng.random() < 0.6
    perms = [ef.permission("*", "*")] if privileged else [env.access_statement(env.random_resource(), write=False)]
    service_trust = ef.trust_policy(ef.trust_statement({"Service": "ec2.amazonaws.com"}))
    target = env.add_role(service_trust, perms, prefix="AdminRole" if privileged else "ServiceRole")
    if privileged:
        env.privileged_roles.add(target["name"])
    env.pass_role_targets.add(target["name"])
    env.rng.choice(env.reachable_roles())["permissions"].append(ef.permission("iam:PassRole", ef.role_arn(target["name"])))


def inject_assume_chain(env: Environment) -> None:
    """User -> R1 -> ... -> Rk (k = 2..4) -> resource."""
    previous = env.random_user_name()
    length = env.rng.randint(2, 4)
    for hop in range(length):
        last = hop == length - 1
        perms = [env.access_statement(env.random_resource(), write=env.rng.random() < 0.4)] if last else []
        trust = ef.trust_policy(ef.trust_statement({"AWS": previous}, condition=env.maybe_condition("mfa", 0.2)))
        previous = env.add_role(trust, perms, prefix="ChainRole")["name"]


def inject_external_trust(env: Environment) -> None:
    """A role trusts an undeclared partner principal."""
    trust = ef.trust_policy(ef.trust_statement({"AWS": env.names.new("partner-")}, condition=env.maybe_condition("external_id", 0.4)))
    env.add_role(trust, [env.access_statement(env.random_resource(), write=env.rng.random() < 0.3)])


def inject_cross_account(env: Environment) -> None:
    """A role trusts a raw foreign AWS account id."""
    trust = ef.trust_policy(ef.trust_statement({"AWS": ef.random_account_id(env.rng)}, condition=env.maybe_condition("external_id", 0.3)))
    res = env.random_resource()
    perm = ef.permission(f"{res['type']}:*", res["arn"]) if env.rng.random() < 0.5 else env.access_statement(res, write=False)
    env.add_role(trust, [perm])


def inject_wildcard_trust(env: Environment) -> None:
    """A role trusts ``Principal: "*"`` -- assumable by anyone."""
    trust = ef.trust_policy(ef.trust_statement("*", condition=env.maybe_condition("source_ip", 0.3)))
    env.add_role(trust, [env.access_statement(env.random_resource(), write=False)])


def inject_policy_modification(env: Environment) -> None:
    """A reachable role can rewrite a managed IAM policy."""
    policy = env.add_resource("iam_policy")
    action = env.rng.choice(["iam:CreatePolicyVersion", "iam:PutRolePolicy", "iam:AttachRolePolicy"])
    env.rng.choice(env.reachable_roles())["permissions"].append(ef.permission(action, policy["arn"]))


def inject_admin_wildcard(env: Environment) -> None:
    """A reachable role holds ``*`` or ``iam:*`` -- administrator-equivalent."""
    action = env.rng.choice(["*", "iam:*"])
    env.rng.choice(env.reachable_roles())["permissions"].append(ef.permission(action, "*"))
    if action == "iam:*":
        # iam:* never matches data resources, so give the pattern a reachable IAM target.
        env.add_resource("iam_policy")


# pattern name -> (injector, relative weight)
PATTERNS: Dict[str, Tuple[Callable[[Environment], None], int]] = {
    "wildcard_action": (inject_wildcard_action, 3),
    "wildcard_resource": (inject_wildcard_resource, 3),
    "pass_role": (inject_pass_role, 3),
    "assume_chain": (inject_assume_chain, 3),
    "external_trust": (inject_external_trust, 2),
    "cross_account": (inject_cross_account, 2),
    "wildcard_trust": (inject_wildcard_trust, 1),
    "policy_modification": (inject_policy_modification, 2),
    "admin_wildcard": (inject_admin_wildcard, 1),
}

# Number of patterns injected per environment -> probability.
PATTERN_COUNT_WEIGHTS = {0: 0.10, 1: 0.35, 2: 0.35, 3: 0.20}


def build_environment(rng: random.Random, scenario_id: str, patterns: Optional[List[str]] = None) -> Scenario:
    """Build one environment. ``patterns`` forces a specific pattern list (used by tests)."""
    env = Environment(rng=rng, scenario_id=scenario_id, names=ef.NameAllocator(rng))
    _build_baseline(env)

    if patterns is None:
        k = rng.choices(list(PATTERN_COUNT_WEIGHTS), weights=list(PATTERN_COUNT_WEIGHTS.values()), k=1)[0]
        names = list(PATTERNS)
        weights = [PATTERNS[n][1] for n in names]
        patterns = []
        while len(patterns) < k:
            pick = rng.choices(names, weights=weights, k=1)[0]
            if pick not in patterns:
                patterns.append(pick)

    for name in patterns:
        PATTERNS[name][0](env)
        env.patterns.append(name)

    raw = {
        "scenario_id": scenario_id,
        "users": env.users,
        "roles": env.roles,
        "resources": env.resources,
    }
    meta = {
        "sensitive_resources": sorted(r["name"] for r in env.resources if r.get("sensitive")),
        "resource_tiers": env.resource_tiers,
        "resource_types": env.resource_types,
        "privileged_roles": sorted(env.privileged_roles),
        "pass_role_targets": sorted(env.pass_role_targets),
        "patterns": list(env.patterns),
    }
    return raw, meta
