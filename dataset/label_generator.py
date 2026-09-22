"""Ground-truth risk oracle for synthetic attack paths (CLAUDE.md section 5.4).

Labels are *not* a rule over the model's own feature columns (that would make
the ML task circular). Instead the oracle scores each path as

    risk_score = impact * (floor + (1 - floor) * likelihood)        # floor = 0.35

using generator-side ground truth the model only sees partially:

- **impact** -- the target's true data classification tier (the model sees
  only an imperfect DataClassification *tag*, missing on ~15% of resources),
  whether the path grants administrator
  or policy-rewrite power, whether a passed role is actually privileged, and
  write vs. read access.
- **likelihood** -- exposure of the entry point (public / external /
  cross-account / internal), attack chain length, and the specific mitigating
  controls on the path (MFA, source-IP, ExternalId; the model sees only that
  *some* condition exists and how many keys it has).

All weights live in ``OracleConfig``. The score is bucketed into
LOW / MEDIUM / HIGH / CRITICAL by fixed cut points.
Everything is deterministic: the same path and scenario always get the same label.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from . import path_signals
from .row_builder import node_name

DEFAULT_TIER = 1
TIER_CAUSE = ("public_data", "internal_data", "confidential_data", "restricted_data")


@dataclass(frozen=True)
class OracleConfig:
    """All oracle weights in one place, so sensitivity analyses can perturb them."""

    # Impact of reaching data by true classification tier (public .. restricted).
    tier_impact: Tuple[float, float, float, float] = (0.10, 0.30, 0.60, 0.85)
    admin_impact: float = 0.95
    policy_modification_impact: float = 0.90
    privileged_pass_role_impact: float = 0.90
    unprivileged_pass_role_impact: float = 0.35
    write_access_bonus: float = 0.10
    # Likelihood that the entry identity is attacker-controlled.
    exposure: Dict[str, float] = field(default_factory=lambda: {"wildcard": 1.00, "external": 0.90, "internal": 0.60})
    hop_decay: float = 0.90
    mitigation_factor: Dict[str, float] = field(default_factory=lambda: {"mfa": 0.45, "source_ip": 0.60, "external_id": 0.65})
    likelihood_floor: float = 0.35
    # risk_score cut points: [0, LOW) -> LOW, [LOW, MEDIUM) -> MEDIUM, ...
    thresholds: Tuple[Tuple[str, float], ...] = (("LOW", 0.20), ("MEDIUM", 0.36), ("HIGH", 0.55))


DEFAULT_ORACLE = OracleConfig()
THRESHOLDS = DEFAULT_ORACLE.thresholds


def _impact(path: Dict[str, Any], row: Dict[str, Any], meta: Dict[str, Any], cfg: OracleConfig) -> Tuple[float, str]:
    target = path["target"]
    name = node_name(target)
    candidates: List[Tuple[float, str]] = []

    if target.startswith("role:"):
        if name in meta.get("privileged_roles", []):
            candidates.append((cfg.privileged_pass_role_impact, "pass_role_to_privileged_role"))
        else:
            candidates.append((cfg.unprivileged_pass_role_impact, "pass_role_to_service_role"))
    else:
        tier = meta.get("resource_tiers", {}).get(name, DEFAULT_TIER)
        impact = cfg.tier_impact[tier] + (cfg.write_access_bonus if row["write_access"] else 0.0)
        candidates.append((min(1.0, impact), TIER_CAUSE[tier] + ("_write" if row["write_access"] else "")))

    if row["admin_permission"]:
        candidates.append((cfg.admin_impact, "admin_permission"))
    if row["policy_modification"]:
        candidates.append((cfg.policy_modification_impact, "policy_modification"))
    return max(candidates)


def _likelihood(path: Dict[str, Any], row: Dict[str, Any], cfg: OracleConfig) -> Tuple[float, List[str]]:
    causes: List[str] = []
    if row["wildcard_principal"]:
        exposure = cfg.exposure["wildcard"]
        causes.append("public_trust")
    elif row["cross_account"]:
        exposure = cfg.exposure["external"]
        causes.append("cross_account")
    elif row["external_trust"]:
        exposure = cfg.exposure["external"]
        causes.append("external_trust")
    else:
        exposure = cfg.exposure["internal"]

    likelihood = exposure * cfg.hop_decay ** max(0, row["path_length"] - 1)
    if row["path_length"] >= 4:
        causes.append("long_chain")
    for kind in path_signals.condition_kinds(path["edges"]):
        likelihood *= cfg.mitigation_factor[kind]
        causes.append(f"{kind}_mitigated")
    return likelihood, causes


def attack_type(row: Dict[str, Any]) -> str:
    if row["cross_account"] or (row["assume_role"] and row["role_count"] >= 2):
        return "Lateral Movement"
    if row["pass_role"] or row["admin_permission"] or row["policy_modification"]:
        return "Privilege Escalation"
    return "Data Access"


def label_for_score(score: float, cfg: OracleConfig = DEFAULT_ORACLE) -> str:
    for label, upper in cfg.thresholds:
        if score < upper:
            return label
    return "CRITICAL"


def assess(
    path: Dict[str, Any], row: Dict[str, Any], meta: Dict[str, Any], cfg: OracleConfig = DEFAULT_ORACLE
) -> Tuple[str, float, str, str]:
    """Return ``(risk_label, risk_score, attack_type, risk_cause)`` for one path.

    ``path`` is an ``AttackPath.to_dict()``, ``row`` its ``build_feature_row``
    output, and ``meta`` the scenario's ground truth from ``build_environment``.
    """
    impact, impact_cause = _impact(path, row, meta, cfg)
    likelihood, likelihood_causes = _likelihood(path, row, cfg)
    score = round(impact * (cfg.likelihood_floor + (1 - cfg.likelihood_floor) * likelihood), 4)
    cause = " + ".join([impact_cause] + likelihood_causes)
    return label_for_score(score, cfg), score, attack_type(row), cause
