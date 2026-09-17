"""Unit tests for graph data models (Node, Edge, DirectedAttackGraph)."""

import unittest
from graph.models import DirectedAttackGraph, Edge, Node


class TestGraphModels(unittest.TestCase):
    """Test Node, Edge, and DirectedAttackGraph structures."""

    def test_node_creation_and_dict(self):
        node = Node(
            id="user:UserA",
            type="user",
            name="UserA",
            arn="arn:aws:iam::123456789012:user/UserA",
            resource_type=None,
        )
        data = node.to_dict()
        self.assertEqual(data["id"], "user:UserA")
        self.assertEqual(data["type"], "user")
        self.assertEqual(data["name"], "UserA")
        self.assertEqual(data["arn"], "arn:aws:iam::123456789012:user/UserA")

    def test_edge_creation_and_dict(self):
        edge = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            effect="Allow",
            actions=["sts:AssumeRole"],
            resources=[],
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        data = edge.to_dict()
        self.assertEqual(data["source"], "user:UserA")
        self.assertEqual(data["target"], "role:RoleA")
        self.assertEqual(data["edge_type"], "CAN_ASSUME")
        self.assertEqual(data["effect"], "Allow")
        self.assertEqual(data["actions"], ["sts:AssumeRole"])
        self.assertEqual(data["conditions"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

    def test_edge_deduplication(self):
        graph = DirectedAttackGraph(scenario_id="dedup_test")
        edge1 = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            effect="Allow",
            actions=["sts:AssumeRole"],
        )
        edge2 = Edge(
            source="user:UserA",
            target="role:RoleA",
            edge_type="CAN_ASSUME",
            effect="Allow",
            actions=["sts:AssumeRole"],
        )
        added1 = graph.add_edge(edge1)
        added2 = graph.add_edge(edge2)
        self.assertTrue(added1)
        self.assertFalse(added2)
        self.assertEqual(len(graph.edges), 1)

    def test_node_deduplication_and_merging(self):
        graph = DirectedAttackGraph(scenario_id="node_dedup_test")
        node1 = Node(id="role:RoleA", type="role", name="RoleA")
        node2 = Node(
            id="role:RoleA",
            type="role",
            name="RoleA",
            arn="arn:aws:iam::123:role/RoleA",
        )
        graph.add_node(node1)
        graph.add_node(node2)
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.get_node("role:RoleA").arn, "arn:aws:iam::123:role/RoleA")

    def test_edge_filtering_queries(self):
        graph = DirectedAttackGraph(scenario_id="query_test")
        graph.add_edge(
            Edge(
                source="user:UserA",
                target="role:RoleA",
                edge_type="CAN_ASSUME",
                effect="Allow",
            )
        )
        graph.add_edge(
            Edge(
                source="role:RoleA",
                target="resource:BucketA",
                edge_type="CAN_ACCESS",
                effect="Allow",
            )
        )
        graph.add_edge(
            Edge(
                source="role:RoleA",
                target="resource:BucketA",
                edge_type="CAN_MODIFY",
                effect="Deny",
            )
        )

        self.assertEqual(len(graph.get_edges(source="user:UserA")), 1)
        self.assertEqual(len(graph.get_edges(source="role:RoleA")), 2)
        self.assertEqual(len(graph.get_edges(edge_type="CAN_ACCESS")), 1)
        self.assertEqual(len(graph.get_edges(effect="Deny")), 1)
        self.assertEqual(len(graph.get_edges(target="resource:BucketA", effect="Allow")), 1)


if __name__ == "__main__":
    unittest.main()
