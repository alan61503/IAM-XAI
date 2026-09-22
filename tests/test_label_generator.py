"""Tests for the ground-truth risk oracle (dataset/label_generator.py)."""

import unittest

from dataset.label_generator import THRESHOLDS, assess, label_for_score


def _row(**overrides):
    base = {
        "path_length": 2,
        "role_count": 1,
        "assume_role": 1,
        "pass_role": 0,
        "wildcard_action": 0,
        "wildcard_resource": 0,
        "policy_modification": 0,
        "external_trust": 0,
        "cross_account": 0,
        "wildcard_principal": 0,
        "sensitive_target": 0,
        "admin_permission": 0,
        "write_access": 0,
    }
    base.update(overrides)
    return base


def _path(target="resource:Data1", conditions=None):
    return {
        "target": target,
        "edges": [
            {"source": "user:U", "target": "role:R", "edge_type": "CAN_ASSUME", "conditions": conditions or {}},
            {"source": "role:R", "target": target, "edge_type": "CAN_ACCESS", "conditions": {}},
        ],
    }


def _meta(tier=1, privileged=()):
    return {"resource_tiers": {"Data1": tier}, "privileged_roles": list(privileged)}


class TestLabelGenerator(unittest.TestCase):
    def test_label_for_score_respects_thresholds(self):
        (_, low), (_, medium), (_, high) = THRESHOLDS
        self.assertEqual(label_for_score(low - 0.001), "LOW")
        self.assertEqual(label_for_score(low), "MEDIUM")
        self.assertEqual(label_for_score(medium), "HIGH")
        self.assertEqual(label_for_score(high), "CRITICAL")

    def test_higher_classification_tier_scores_higher(self):
        scores = [assess(_path(), _row(), _meta(tier=t))[1] for t in range(4)]
        self.assertEqual(scores, sorted(scores))
        self.assertLess(scores[0], scores[3])

    def test_public_data_via_internal_user_is_low(self):
        label, _, _, cause = assess(_path(), _row(), _meta(tier=0))
        self.assertEqual(label, "LOW")
        self.assertIn("public_data", cause)

    def test_admin_permission_is_critical_regardless_of_target_tier(self):
        label, _, attack_type, cause = assess(_path(), _row(admin_permission=1), _meta(tier=0))
        self.assertEqual(label, "CRITICAL")
        self.assertEqual(attack_type, "Privilege Escalation")
        self.assertTrue(cause.startswith("admin_permission"))

    def test_external_exposure_raises_risk(self):
        internal = assess(_path(), _row(), _meta(tier=2))[1]
        external = assess(_path(), _row(external_trust=1), _meta(tier=2))[1]
        self.assertGreater(external, internal)

    def test_mfa_condition_lowers_risk_and_is_named_in_cause(self):
        mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        plain = assess(_path(), _row(), _meta(tier=3))[1]
        label, mitigated, _, cause = assess(_path(conditions=mfa), _row(), _meta(tier=3))
        self.assertLess(mitigated, plain)
        self.assertIn("mfa_mitigated", cause)

    def test_pass_role_depends_on_whether_target_role_is_privileged(self):
        path = _path(target="role:Admin")
        row = _row(pass_role=1)
        privileged = assess(path, row, _meta(privileged=["Admin"]))
        unprivileged = assess(path, row, _meta())
        self.assertGreater(privileged[1], unprivileged[1])
        self.assertIn("pass_role_to_privileged_role", privileged[3])

    def test_assessment_is_deterministic(self):
        args = (_path(), _row(external_trust=1, write_access=1), _meta(tier=2))
        self.assertEqual(assess(*args), assess(*args))


if __name__ == "__main__":
    unittest.main()
