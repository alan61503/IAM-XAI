"""Tests for the deterministic risk-labeling rules (CLAUDE.md section 5.4)."""

import unittest

from dataset.label_generator import classify


def _row(**overrides):
    base = {
        "path_length": 1,
        "role_count": 1,
        "assume_role": 0,
        "pass_role": 0,
        "wildcard_action": 0,
        "wildcard_resource": 0,
        "policy_modification": 0,
        "external_trust": 0,
        "cross_account": 0,
        "sensitive_target": 0,
        "admin_permission": 0,
    }
    base.update(overrides)
    return base


class TestLabelGenerator(unittest.TestCase):
    def test_plain_read_only_is_low(self):
        label, score, attack_type, cause = classify(_row())
        self.assertEqual(label, "LOW")
        self.assertEqual(cause, "read_only_access")
        self.assertEqual(attack_type, "Data Access")

    def test_wildcard_action_is_medium(self):
        label, _, _, cause = classify(_row(wildcard_action=1))
        self.assertEqual(label, "MEDIUM")
        self.assertIn("wildcard_action", cause)

    def test_pass_role_is_high(self):
        label, _, _, cause = classify(_row(pass_role=1))
        self.assertEqual(label, "HIGH")
        self.assertIn("pass_role", cause)

    def test_role_chain_is_high(self):
        label, _, attack_type, cause = classify(_row(assume_role=1, role_count=2))
        self.assertEqual(label, "HIGH")
        self.assertIn("assume_role_chain", cause)
        self.assertEqual(attack_type, "Lateral Movement")

    def test_long_chain_is_high(self):
        label, _, _, cause = classify(_row(path_length=4))
        self.assertEqual(label, "HIGH")
        self.assertIn("long_privilege_escalation_chain", cause)

    def test_external_trust_is_critical(self):
        label, _, _, cause = classify(_row(external_trust=1))
        self.assertEqual(label, "CRITICAL")
        self.assertIn("external_trust", cause)

    def test_cross_account_is_critical(self):
        label, _, attack_type, _ = classify(_row(cross_account=1))
        self.assertEqual(label, "CRITICAL")
        self.assertEqual(attack_type, "Lateral Movement")

    def test_policy_modification_is_critical(self):
        label, _, attack_type, cause = classify(_row(policy_modification=1))
        self.assertEqual(label, "CRITICAL")
        self.assertIn("policy_modification", cause)
        self.assertEqual(attack_type, "Privilege Escalation")

    def test_admin_permission_is_critical(self):
        label, _, attack_type, cause = classify(_row(admin_permission=1))
        self.assertEqual(label, "CRITICAL")
        self.assertEqual(attack_type, "Privilege Escalation")

    def test_wildcard_plus_sensitive_is_critical(self):
        label, _, _, cause = classify(_row(wildcard_action=1, sensitive_target=1))
        self.assertEqual(label, "CRITICAL")
        self.assertIn("wildcard_action+sensitive_target", cause)

    def test_wildcard_without_sensitive_is_not_critical(self):
        label, _, _, _ = classify(_row(wildcard_action=1, sensitive_target=0))
        self.assertNotEqual(label, "CRITICAL")

    def test_critical_takes_priority_over_high_and_medium(self):
        label, _, _, cause = classify(
            _row(wildcard_action=1, pass_role=1, admin_permission=1)
        )
        self.assertEqual(label, "CRITICAL")
        self.assertIn("admin_permission", cause)

    def test_score_increases_with_more_causes(self):
        _, score_one, _, _ = classify(_row(admin_permission=1))
        _, score_two, _, _ = classify(_row(admin_permission=1, external_trust=1))
        self.assertGreaterEqual(score_two, score_one)


if __name__ == "__main__":
    unittest.main()
