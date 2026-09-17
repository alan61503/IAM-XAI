"""Unit tests for resource_matcher module."""

import unittest
from graph.action_mapper import EDGE_TYPE_ACCESS, EDGE_TYPE_ASSUME
from graph.models import Node
from graph.resource_matcher import ResourceMatcher


class TestResourceMatcher(unittest.TestCase):
    """Test resource ARN pattern matching against graph nodes."""

    def setUp(self):
        self.matcher = ResourceMatcher()
        self.s3_node = Node(
            id="resource:ExampleBucket",
            type="resource",
            name="ExampleBucket",
            arn="arn:aws:s3:::example-bucket",
            resource_type="s3",
        )
        self.role_node = Node(
            id="role:TargetRoleB",
            type="role",
            name="TargetRoleB",
            arn="arn:aws:iam::123456789012:role/TargetRoleB",
        )
        self.dynamo_node = Node(
            id="resource:AppTable",
            type="resource",
            name="AppTable",
            arn="arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
            resource_type="dynamodb",
        )

    def test_s3_object_arn_matches_bucket(self):
        # arn:aws:s3:::example-bucket/* should match bucket node
        pattern = "arn:aws:s3:::example-bucket/*"
        self.assertTrue(self.matcher.matches(pattern, self.s3_node))
        self.assertFalse(self.matcher.matches(pattern, self.dynamo_node))

    def test_s3_subfolder_arn_matches_bucket(self):
        pattern = "arn:aws:s3:::example-bucket/folder/subfolder/*"
        self.assertTrue(self.matcher.matches(pattern, self.s3_node))

    def test_exact_arn_match(self):
        self.assertTrue(
            self.matcher.matches(
                "arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
                self.dynamo_node,
            )
        )

    def test_role_arn_matches_role_node(self):
        pattern = "arn:aws:iam::123456789012:role/TargetRoleB"
        self.assertTrue(
            self.matcher.matches(pattern, self.role_node, edge_type=EDGE_TYPE_ASSUME)
        )

    def test_wildcard_star(self):
        # '*' on CAN_ACCESS should match resource nodes, not roles
        self.assertTrue(self.matcher.matches("*", self.s3_node, edge_type=EDGE_TYPE_ACCESS))
        self.assertFalse(self.matcher.matches("*", self.role_node, edge_type=EDGE_TYPE_ACCESS))

        # '*' on CAN_ASSUME should match role nodes
        self.assertTrue(self.matcher.matches("*", self.role_node, edge_type=EDGE_TYPE_ASSUME))

    def test_s3_service_wildcard(self):
        pattern = "arn:aws:s3:::*"
        self.assertTrue(self.matcher.matches(pattern, self.s3_node))
        self.assertFalse(self.matcher.matches(pattern, self.dynamo_node))

    def test_find_matching_nodes(self):
        nodes = [self.s3_node, self.role_node, self.dynamo_node]
        matches = self.matcher.find_matching_nodes("arn:aws:s3:::example-bucket/*", nodes)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].id, "resource:ExampleBucket")


if __name__ == "__main__":
    unittest.main()
