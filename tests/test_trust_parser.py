"""Unit tests for trust_parser module."""

import unittest
from parser.policy_parser import IAMValidationError
from parser.trust_parser import (
    parse_trust_statement,
    parse_trust_policy,
)


class TestTrustParser(unittest.TestCase):
    """Test trust policy and relationship parsing logic."""

    def test_single_aws_principal(self):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": "UserA"},
            "Action": "sts:AssumeRole",
        }
        rels = parse_trust_statement(stmt, target_role="RoleA")
        self.assertEqual(len(rels), 1)
        rel = rels[0]
        self.assertEqual(rel["source"], "UserA")
        self.assertEqual(rel["target"], "RoleA")
        self.assertEqual(rel["effect"], "Allow")
        self.assertEqual(rel["actions"], ["sts:AssumeRole"])
        self.assertEqual(rel["conditions"], {})

    def test_multiple_aws_principals(self):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": ["UserA", "UserB", "RoleX"]},
            "Action": "sts:AssumeRole",
        }
        rels = parse_trust_statement(stmt, target_role="TargetRole")
        self.assertEqual(len(rels), 3)
        sources = [r["source"] for r in rels]
        self.assertEqual(sources, ["UserA", "UserB", "RoleX"])
        for r in rels:
            self.assertEqual(r["target"], "TargetRole")
            self.assertEqual(r["actions"], ["sts:AssumeRole"])

    def test_service_principal(self):
        stmt = {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
        rels = parse_trust_statement(stmt, target_role="EC2Role")
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["source"], "ec2.amazonaws.com")
        self.assertEqual(rels[0]["target"], "EC2Role")

    def test_mixed_principals_aws_and_service(self):
        stmt = {
            "Effect": "Allow",
            "Principal": {
                "AWS": "UserA",
                "Service": "lambda.amazonaws.com",
            },
            "Action": "sts:AssumeRole",
        }
        rels = parse_trust_statement(stmt, target_role="MultiRole")
        self.assertEqual(len(rels), 2)
        sources = {r["source"] for r in rels}
        self.assertEqual(sources, {"UserA", "lambda.amazonaws.com"})

    def test_wildcard_principals(self):
        # Dict with wildcard
        stmt_dict = {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
        }
        rels1 = parse_trust_statement(stmt_dict, target_role="OpenRole")
        self.assertEqual(len(rels1), 1)
        self.assertEqual(rels1[0]["source"], "*")

        # Direct string wildcard
        stmt_str = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }
        rels2 = parse_trust_statement(stmt_str, target_role="OpenRole")
        self.assertEqual(len(rels2), 1)
        self.assertEqual(rels2[0]["source"], "*")

    def test_trust_policy_with_conditions(self):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": "UserMFA"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"}
            },
        }
        rels = parse_trust_statement(stmt, target_role="MFARole")
        self.assertEqual(len(rels), 1)
        self.assertEqual(
            rels[0]["conditions"],
            {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )

    def test_trust_policy_deny_effect(self):
        stmt = {
            "Effect": "Deny",
            "Principal": {"AWS": "BlockedUser"},
            "Action": "sts:AssumeRole",
        }
        rels = parse_trust_statement(stmt, target_role="SecureRole")
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["effect"], "Deny")

    def test_parse_trust_policy_full_structure(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "UserA"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }
        rels = parse_trust_policy(policy, target_role="RoleA")
        self.assertEqual(len(rels), 2)
        self.assertEqual(rels[0]["source"], "UserA")
        self.assertEqual(rels[1]["source"], "ec2.amazonaws.com")

    def test_parse_trust_policy_empty_or_none(self):
        self.assertEqual(parse_trust_policy(None, "RoleA"), [])

    # Error handling tests
    def test_missing_principal_raises_error(self):
        stmt = {"Effect": "Allow", "Action": "sts:AssumeRole"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_trust_statement(stmt, target_role="RoleA")
        self.assertIn("Missing 'Principal'", str(ctx.exception))

    def test_empty_principal_dict_raises_error(self):
        stmt = {"Effect": "Allow", "Principal": {}, "Action": "sts:AssumeRole"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_trust_statement(stmt, target_role="RoleA")
        self.assertIn("'Principal' object cannot be empty", str(ctx.exception))

    def test_missing_action_in_trust_raises_error(self):
        stmt = {"Effect": "Allow", "Principal": {"AWS": "UserA"}}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_trust_statement(stmt, target_role="RoleA")
        self.assertIn("Missing 'Action'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
