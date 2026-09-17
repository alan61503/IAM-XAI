"""Unit tests for TraversalPolicy in Phase 3."""

import unittest
from graph.models import Edge, Node
from path.traversal_policy import TraversalPolicy


class TestTraversalPolicy(unittest.TestCase):
    """Test traversal rules and semantics."""

    def setUp(self):
        self.policy = TraversalPolicy()

    def test_allow_edge_is_traversable(self):
        edge = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            effect="Allow",
        )
        self.assertTrue(self.policy.is_traversable_edge(edge))

    def test_deny_edge_is_not_traversable(self):
        edge = Edge(
            source="role:RoleA",
            target="resource:SecretBucket",
            edge_type="CAN_MODIFY",
            effect="Deny",
        )
        self.assertFalse(self.policy.is_traversable_edge(edge))

    def test_can_pivot_into_role_via_can_assume(self):
        edge = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            effect="Allow",
        )
        role_node = Node(id="role:RoleA", type="role", name="RoleA")
        self.assertTrue(self.policy.can_pivot_into_node(edge, role_node))

    def test_cannot_pivot_via_can_pass_role(self):
        # PassRole does NOT allow pivoting into the target role
        edge = Edge(
            source="role:RoleA",
            target="role:RoleB",
            edge_type="CAN_PASS_ROLE",
            effect="Allow",
        )
        role_node = Node(id="role:RoleB", type="role", name="RoleB")
        self.assertFalse(self.policy.can_pivot_into_node(edge, role_node))

    def test_cannot_pivot_into_resource_via_access_or_modify(self):
        res_node = Node(id="resource:BucketA", type="resource", name="BucketA")
        edge_access = Edge(
            source="role:RoleA",
            target="resource:BucketA",
            edge_type="CAN_ACCESS",
            effect="Allow",
        )
        edge_modify = Edge(
            source="role:RoleA",
            target="resource:BucketA",
            edge_type="CAN_MODIFY",
            effect="Allow",
        )
        self.assertFalse(self.policy.can_pivot_into_node(edge_access, res_node))
        self.assertFalse(self.policy.can_pivot_into_node(edge_modify, res_node))

    def test_is_valid_source_user_vs_role(self):
        user_node = Node(id="user:UserA", type="user", name="UserA")
        role_node = Node(id="role:RoleA", type="role", name="RoleA")
        res_node = Node(id="resource:BucketA", type="resource", name="BucketA")

        self.assertTrue(self.policy.is_valid_source(user_node))
        self.assertFalse(self.policy.is_valid_source(role_node))
        self.assertFalse(self.policy.is_valid_source(res_node))

    def test_is_valid_target_resource_vs_user(self):
        res_node = Node(id="resource:BucketA", type="resource", name="BucketA")
        sensitive_role = Node(
            id="role:AdminRole",
            type="role",
            name="AdminRole",
            metadata={"sensitive": True},
        )
        user_node = Node(id="user:UserA", type="user", name="UserA")

        self.assertTrue(self.policy.is_valid_target(res_node))
        self.assertTrue(self.policy.is_valid_target(sensitive_role))
        self.assertFalse(self.policy.is_valid_target(user_node))

    def test_conditional_path_detection(self):
        uncond_edge = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            conditions={},
        )
        cond_edge = Edge(
            source="role:RoleA",
            target="resource:BucketA",
            edge_type="CAN_ACCESS",
            conditions={"IpAddress": {"aws:SourceIp": "10.0.0.0/16"}},
        )

        self.assertFalse(self.policy.is_conditional_path([uncond_edge]))
        self.assertTrue(self.policy.is_conditional_path([uncond_edge, cond_edge]))


if __name__ == "__main__":
    unittest.main()
