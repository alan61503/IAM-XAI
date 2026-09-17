"""Unit tests for action_mapper module."""

import unittest
from graph.action_mapper import (
    ActionMapper,
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_MODIFY,
    EDGE_TYPE_PASS_ROLE,
)


class TestActionMapper(unittest.TestCase):
    """Test action classification and wildcard handling."""

    def setUp(self):
        self.mapper = ActionMapper()

    def test_assume_role_actions(self):
        self.assertEqual(
            self.mapper.classify_action("sts:AssumeRole"),
            {EDGE_TYPE_ASSUME},
        )
        self.assertEqual(
            self.mapper.classify_action("sts:AssumeRoleWithSAML"),
            {EDGE_TYPE_ASSUME},
        )

    def test_pass_role_action(self):
        result = self.mapper.classify_action("iam:PassRole")
        self.assertEqual(result, {EDGE_TYPE_PASS_ROLE})
        self.assertNotIn(EDGE_TYPE_ASSUME, result)

    def test_s3_read_actions(self):
        self.assertEqual(
            self.mapper.classify_action("s3:GetObject"),
            {EDGE_TYPE_ACCESS},
        )
        self.assertEqual(
            self.mapper.classify_action("s3:ListBucket"),
            {EDGE_TYPE_ACCESS},
        )

    def test_s3_write_actions(self):
        self.assertEqual(
            self.mapper.classify_action("s3:PutObject"),
            {EDGE_TYPE_MODIFY},
        )
        self.assertEqual(
            self.mapper.classify_action("s3:DeleteObject"),
            {EDGE_TYPE_MODIFY},
        )

    def test_service_wildcards(self):
        s3_wildcard = self.mapper.classify_action("s3:*")
        self.assertIn(EDGE_TYPE_ACCESS, s3_wildcard)
        self.assertIn(EDGE_TYPE_MODIFY, s3_wildcard)

        sts_wildcard = self.mapper.classify_action("sts:*")
        self.assertIn(EDGE_TYPE_ASSUME, sts_wildcard)

    def test_full_wildcard(self):
        full_wildcard = self.mapper.classify_action("*")
        self.assertIn(EDGE_TYPE_ACCESS, full_wildcard)
        self.assertIn(EDGE_TYPE_MODIFY, full_wildcard)
        # Verify conservative handling: '*' does NOT map to CAN_ASSUME or CAN_PASS_ROLE
        self.assertNotIn(EDGE_TYPE_ASSUME, full_wildcard)
        self.assertNotIn(EDGE_TYPE_PASS_ROLE, full_wildcard)

    def test_group_actions_by_edge_type(self):
        actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        grouped = self.mapper.group_actions_by_edge_type(actions)
        self.assertIn(EDGE_TYPE_ACCESS, grouped)
        self.assertIn(EDGE_TYPE_MODIFY, grouped)
        self.assertEqual(grouped[EDGE_TYPE_ACCESS], ["s3:GetObject"])
        self.assertEqual(grouped[EDGE_TYPE_MODIFY], ["s3:PutObject", "s3:DeleteObject"])

    def test_extensibility_custom_registration(self):
        self.mapper.register_exact_mapping("custom:ActionRead", {EDGE_TYPE_ACCESS})
        self.assertEqual(
            self.mapper.classify_action("custom:ActionRead"),
            {EDGE_TYPE_ACCESS},
        )
        self.mapper.register_prefix_mapping("custom:admin*", {EDGE_TYPE_MODIFY})
        self.assertEqual(
            self.mapper.classify_action("custom:adminReset"),
            {EDGE_TYPE_MODIFY},
        )


if __name__ == "__main__":
    unittest.main()
