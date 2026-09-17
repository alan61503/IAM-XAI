"""Unit tests for policy_parser module."""

import unittest
from parser.policy_parser import (
    IAMValidationError,
    parse_permission_statement,
    parse_permissions,
)


class TestPolicyParser(unittest.TestCase):
    """Test policy and permission parsing logic."""

    def test_single_action_and_single_resource(self):
        stmt = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
        res = parse_permission_statement(stmt, source="RoleA")
        self.assertEqual(res["source"], "RoleA")
        self.assertEqual(res["effect"], "Allow")
        self.assertEqual(res["actions"], ["s3:GetObject"])
        self.assertEqual(res["resources"], ["arn:aws:s3:::my-bucket/*"])
        self.assertEqual(res["conditions"], {})

    def test_multiple_actions_and_resources(self):
        stmt = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": [
                "arn:aws:s3:::bucket-1/*",
                "arn:aws:s3:::bucket-2/*",
            ],
        }
        res = parse_permission_statement(stmt, source="RoleB")
        self.assertEqual(res["actions"], ["s3:GetObject", "s3:PutObject"])
        self.assertEqual(
            res["resources"],
            ["arn:aws:s3:::bucket-1/*", "arn:aws:s3:::bucket-2/*"],
        )

    def test_effect_allow_and_deny(self):
        allow_stmt = {
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*",
        }
        deny_stmt = {
            "Effect": "Deny",
            "Action": "ec2:TerminateInstances",
            "Resource": "*",
        }
        self.assertEqual(parse_permission_statement(allow_stmt)["effect"], "Allow")
        self.assertEqual(parse_permission_statement(deny_stmt)["effect"], "Deny")

        # Case-insensitivity normalization
        lower_stmt = {
            "Effect": "deny",
            "Action": "s3:*",
            "Resource": "*",
        }
        self.assertEqual(parse_permission_statement(lower_stmt)["effect"], "Deny")

    def test_wildcards_preserved_exactly(self):
        stmt = {
            "Effect": "Allow",
            "Action": ["*", "s3:*", "dynamodb:Get*"],
            "Resource": ["*", "arn:aws:s3:::*"],
        }
        res = parse_permission_statement(stmt, source="AdminRole")
        self.assertEqual(res["actions"], ["*", "s3:*", "dynamodb:Get*"])
        self.assertEqual(res["resources"], ["*", "arn:aws:s3:::*"])

    def test_conditions_preserved(self):
        cond = {
            "StringEquals": {"aws:PrincipalTag/Department": "Finance"},
            "IpAddress": {"aws:SourceIp": "192.168.1.0/24"},
        }
        stmt = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::finance-bucket/*",
            "Condition": cond,
        }
        res = parse_permission_statement(stmt)
        self.assertEqual(res["conditions"], cond)

    def test_parse_permissions_multiple_statements_list(self):
        perms = [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
            },
            {
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::bucket/*",
            },
        ]
        parsed = parse_permissions(perms, source="TestRole")
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["effect"], "Allow")
        self.assertEqual(parsed[1]["effect"], "Deny")
        self.assertEqual(parsed[0]["source"], "TestRole")
        self.assertEqual(parsed[1]["source"], "TestRole")

    def test_parse_permissions_policy_document_with_statement_dict(self):
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:*:*:queue",
            },
        }
        parsed = parse_permissions(policy_doc, source="QueueRole")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["actions"], ["sqs:SendMessage"])

    def test_parse_permissions_empty(self):
        self.assertEqual(parse_permissions([], source="Role"), [])
        self.assertEqual(parse_permissions(None, source="Role"), [])

    # Validation and error tests
    def test_missing_effect_raises_error(self):
        stmt = {"Action": "s3:GetObject", "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("Missing required 'Effect'", str(ctx.exception))

    def test_invalid_effect_raises_error(self):
        stmt = {"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("Invalid Effect", str(ctx.exception))

    def test_missing_action_raises_error(self):
        stmt = {"Effect": "Allow", "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("Missing required 'Action'", str(ctx.exception))

    def test_empty_action_raises_error(self):
        stmt = {"Effect": "Allow", "Action": "", "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("cannot be an empty string", str(ctx.exception))

    def test_empty_action_list_raises_error(self):
        stmt = {"Effect": "Allow", "Action": [], "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("cannot be an empty list", str(ctx.exception))

    def test_action_item_non_string_raises_error(self):
        stmt = {"Effect": "Allow", "Action": [123], "Resource": "*"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("must be a string", str(ctx.exception))

    def test_missing_resource_raises_error(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject"}
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("Missing required 'Resource'", str(ctx.exception))

    def test_invalid_condition_type_raises_error(self):
        stmt = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": "not-a-dict",
        }
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement(stmt)
        self.assertIn("'Condition' block must be a JSON object", str(ctx.exception))

    def test_non_dict_statement_raises_error(self):
        with self.assertRaises(IAMValidationError) as ctx:
            parse_permission_statement("invalid")
        self.assertIn("must be a dictionary", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
