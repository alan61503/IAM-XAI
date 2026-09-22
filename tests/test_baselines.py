"""Tests for the static rule-based baseline (the original CLAUDE.md section 5.4 rules)."""

import unittest

import pandas as pd

from models.baselines import predict_rule_based, rule_based_label


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


class TestRuleBasedBaseline(unittest.TestCase):
    def test_plain_read_only_is_low(self):
        self.assertEqual(rule_based_label(_row()), "LOW")

    def test_wildcard_action_is_medium(self):
        self.assertEqual(rule_based_label(_row(wildcard_action=1)), "MEDIUM")

    def test_pass_role_is_high(self):
        self.assertEqual(rule_based_label(_row(pass_role=1)), "HIGH")

    def test_role_chain_is_high(self):
        self.assertEqual(rule_based_label(_row(assume_role=1, role_count=2)), "HIGH")

    def test_long_chain_is_high(self):
        self.assertEqual(rule_based_label(_row(path_length=4)), "HIGH")

    def test_critical_triggers(self):
        for flag in ("external_trust", "cross_account", "policy_modification", "admin_permission"):
            with self.subTest(flag=flag):
                self.assertEqual(rule_based_label(_row(**{flag: 1})), "CRITICAL")

    def test_wildcard_plus_sensitive_is_critical(self):
        self.assertEqual(rule_based_label(_row(wildcard_action=1, sensitive_target=1)), "CRITICAL")

    def test_wildcard_without_sensitive_is_not_critical(self):
        self.assertNotEqual(rule_based_label(_row(wildcard_action=1, sensitive_target=0)), "CRITICAL")

    def test_critical_takes_priority_over_high_and_medium(self):
        self.assertEqual(rule_based_label(_row(wildcard_action=1, pass_role=1, admin_permission=1)), "CRITICAL")

    def test_predict_rule_based_labels_every_row(self):
        df = pd.DataFrame([_row(), _row(pass_role=1), _row(admin_permission=1)])
        self.assertEqual(predict_rule_based(df), ["LOW", "HIGH", "CRITICAL"])


if __name__ == "__main__":
    unittest.main()
