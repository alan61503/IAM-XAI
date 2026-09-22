"""Unit and integration tests for PathFinder across all scenarios and edge cases."""

import unittest
from pathlib import Path

from graph.graph_builder import build_attack_graph
from graph.graph_serializer import load_graph_file
from graph.models import DirectedAttackGraph, Edge, Node
from parser.normalizer import normalize_scenario, normalize_scenario_file
from path.path_finder import PathFinder, find_attack_paths


class TestPathFinder(unittest.TestCase):
    """Test attack path enumeration, multi-hop chains, and cycle handling."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "data" / "scenarios"
        self.finder = PathFinder()

    def _get_scenario_graph(self, filename: str) -> DirectedAttackGraph:
        normalized = normalize_scenario_file(self.scenarios_dir / filename)
        return build_attack_graph(normalized)

    def test_scenario_001_basic_path(self):
        graph = self._get_scenario_graph("scenario_001.json")
        paths = self.finder.find_paths(graph)

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path.scenario_id, "scenario_001")
        self.assertEqual(path.source, "user:UserA")
        self.assertEqual(path.target, "resource:ExampleBucket")
        self.assertEqual(
            path.nodes,
            ["user:UserA", "role:RoleA", "resource:ExampleBucket"],
        )
        self.assertEqual(path.hop_count, 2)
        self.assertFalse(path.conditional)
        self.assertEqual(len(path.edges), 2)
        self.assertEqual(path.edges[0]["edge_type"], "CAN_ASSUME")
        self.assertEqual(path.edges[1]["edge_type"], "CAN_ACCESS")

    def test_scenario_002_multiple_actions_parallel_paths(self):
        graph = self._get_scenario_graph("scenario_002.json")
        paths = self.finder.find_paths(graph)

        # DeveloperUser -> DevRole -> DevBucket via CAN_ACCESS and CAN_MODIFY
        self.assertEqual(len(paths), 2)
        edge_types_found = {p.edges[-1]["edge_type"] for p in paths}
        self.assertEqual(edge_types_found, {"CAN_ACCESS", "CAN_MODIFY"})

    def test_scenario_003_multiple_resources(self):
        graph = self._get_scenario_graph("scenario_003.json")
        paths = self.finder.find_paths(graph)

        # AuditorRole has access to 3 distinct buckets
        self.assertEqual(len(paths), 3)
        targets = {p.target for p in paths}
        self.assertEqual(
            targets,
            {
                "resource:FinanceBucket",
                "resource:HRBucket",
                "resource:ComplianceBucket",
            },
        )

    def test_scenario_004_multiple_statements_ops_user(self):
        graph = self._get_scenario_graph("scenario_004.json")
        paths = self.finder.find_paths(graph, source="user:OpsUser")

        # OpsUser -> MultiStatementRole -> AppDataBucket and AppTable
        self.assertEqual(len(paths), 2)
        targets = {p.target for p in paths}
        self.assertEqual(targets, {"resource:AppDataBucket", "resource:AppTable"})

    def test_scenario_005_deny_not_traversed_as_capability(self):
        graph = self._get_scenario_graph("scenario_005.json")
        paths = self.finder.find_paths(graph)

        # Verify no path traversed a Deny edge
        for path in paths:
            for edge_dict in path.edges:
                self.assertEqual(edge_dict["effect"], "Allow")
                self.assertNotEqual(edge_dict["effect"], "Deny")

    def test_scenario_006_wildcards(self):
        graph = self._get_scenario_graph("scenario_006.json")
        paths = self.finder.find_paths(graph, source="user:SuperUser")

        self.assertTrue(len(paths) > 0)
        for path in paths:
            self.assertEqual(path.source, "user:SuperUser")
            # All traversed edges must be Allow
            for e in path.edges:
                self.assertEqual(e["effect"], "Allow")

    def test_scenario_007_multiple_principals(self):
        graph = self._get_scenario_graph("scenario_007.json")
        paths = self.finder.find_paths(graph)

        # Both UserAlpha and UserBeta have paths to TaskQueue
        sources = {p.source for p in paths}
        self.assertIn("user:UserAlpha", sources)
        self.assertIn("user:UserBeta", sources)
        for p in paths:
            self.assertEqual(p.target, "resource:TaskQueue")

    def test_scenario_008_conditions_preserved_and_flagged(self):
        graph = self._get_scenario_graph("scenario_008.json")
        paths = self.finder.find_paths(graph)

        self.assertEqual(len(paths), 1)
        path = paths[0]
        # Path contains MFA condition on assume and IP condition on access
        self.assertTrue(path.conditional)
        self.assertIn("Bool", path.edges[0]["conditions"])
        self.assertIn("IpAddress", path.edges[1]["conditions"])

    def test_scenario_009_role_chaining_multi_hop(self):
        graph = self._get_scenario_graph("scenario_009.json")
        paths = self.finder.find_paths(
            graph,
            source="user:InitialUser",
            target="resource:ProductionDataBucket",
            max_hops=5,
        )

        self.assertTrue(len(paths) >= 1)
        path = paths[0]
        self.assertEqual(path.source, "user:InitialUser")
        self.assertEqual(path.target, "resource:ProductionDataBucket")
        self.assertEqual(
            path.nodes,
            [
                "user:InitialUser",
                "role:IntermediateRoleA",
                "role:TargetRoleB",
                "resource:ProductionDataBucket",
            ],
        )
        self.assertEqual(path.hop_count, 3)
        self.assertEqual(len(path.edges), 3)

        # Verify edge types along the chain
        self.assertEqual(path.edges[0]["edge_type"], "CAN_ASSUME")
        self.assertEqual(path.edges[1]["edge_type"], "CAN_ASSUME")
        self.assertEqual(path.edges[2]["edge_type"], "CAN_ACCESS")

    # PassRole Semantics Tests
    def test_pass_role_does_not_permit_pivoting(self):
        """A role with CAN_PASS_ROLE alone cannot pivot into the target role."""
        graph = DirectedAttackGraph(scenario_id="pass_role_test")
        graph.add_node(Node(id="user:DevUser", type="user", name="DevUser"))
        graph.add_node(Node(id="role:RoleA", type="role", name="RoleA"))
        graph.add_node(Node(id="role:RoleB", type="role", name="RoleB"))
        graph.add_node(Node(id="resource:TargetBucket", type="resource", name="TargetBucket"))

        # User -> RoleA (CAN_ASSUME)
        graph.add_edge(
            Edge(
                source="user:DevUser",
                target="role:RoleA",
                edge_type="CAN_ASSUME",
                effect="Allow",
            )
        )
        # RoleA -> RoleB (CAN_PASS_ROLE only, NO CAN_ASSUME)
        graph.add_edge(
            Edge(
                source="role:RoleA",
                target="role:RoleB",
                edge_type="CAN_PASS_ROLE",
                effect="Allow",
            )
        )
        # RoleB -> TargetBucket (CAN_ACCESS)
        graph.add_edge(
            Edge(
                source="role:RoleB",
                target="resource:TargetBucket",
                edge_type="CAN_ACCESS",
                effect="Allow",
            )
        )

        # Attacker should NOT be able to traverse RoleA -> RoleB -> TargetBucket
        paths = self.finder.find_paths(graph, source="user:DevUser", target="resource:TargetBucket")
        self.assertEqual(len(paths), 0)

        # Now add genuine CAN_ASSUME from RoleA to RoleB
        graph.add_edge(
            Edge(
                source="role:RoleA",
                target="role:RoleB",
                edge_type="CAN_ASSUME",
                effect="Allow",
            )
        )
        paths_with_assume = self.finder.find_paths(
            graph, source="user:DevUser", target="resource:TargetBucket"
        )
        self.assertEqual(len(paths_with_assume), 1)
        self.assertEqual(paths_with_assume[0].hop_count, 3)

    # Cycle and Simple Path Tests
    def test_cycle_termination_and_simple_paths(self):
        """Ensure cyclic graph terminates and produces simple paths without repeated nodes."""
        graph = DirectedAttackGraph(scenario_id="cycle_test")
        graph.add_node(Node(id="user:Attacker", type="user", name="Attacker"))
        graph.add_node(Node(id="role:Role1", type="role", name="Role1"))
        graph.add_node(Node(id="role:Role2", type="role", name="Role2"))
        graph.add_node(Node(id="resource:Secret", type="resource", name="Secret"))

        # Attacker -> Role1 -> Role2 -> Role1 (cycle)
        graph.add_edge(Edge(source="user:Attacker", target="role:Role1", edge_type="CAN_ASSUME", effect="Allow"))
        graph.add_edge(Edge(source="role:Role1", target="role:Role2", edge_type="CAN_ASSUME", effect="Allow"))
        graph.add_edge(Edge(source="role:Role2", target="role:Role1", edge_type="CAN_ASSUME", effect="Allow"))
        # Role2 -> Secret
        graph.add_edge(Edge(source="role:Role2", target="resource:Secret", edge_type="CAN_ACCESS", effect="Allow"))

        paths = self.finder.find_paths(graph, max_hops=10)
        self.assertTrue(len(paths) >= 1)
        for p in paths:
            # Check simple path condition: no repeated nodes
            self.assertEqual(len(p.nodes), len(set(p.nodes)))

    def test_max_hops_bound_enforced(self):
        graph = self._get_scenario_graph("scenario_009.json")
        # 3-hop path should not be returned if max_hops is 2
        paths_max_2 = self.finder.find_paths(
            graph,
            source="user:InitialUser",
            target="resource:ProductionDataBucket",
            max_hops=2,
        )
        self.assertEqual(len(paths_max_2), 0)

        paths_max_3 = self.finder.find_paths(
            graph,
            source="user:InitialUser",
            target="resource:ProductionDataBucket",
            max_hops=3,
        )
        self.assertTrue(len(paths_max_3) >= 1)

    # Edge cases
    def test_missing_source_returns_empty(self):
        graph = self._get_scenario_graph("scenario_001.json")
        paths = self.finder.find_paths(graph, source="user:NonExistent")
        self.assertEqual(paths, [])

    def test_missing_target_returns_empty(self):
        graph = self._get_scenario_graph("scenario_001.json")
        paths = self.finder.find_paths(graph, target="resource:NonExistent")
        self.assertEqual(paths, [])

    def test_empty_graph_returns_empty(self):
        graph = DirectedAttackGraph(scenario_id="empty")
        paths = self.finder.find_paths(graph)
        self.assertEqual(paths, [])

    def test_disconnected_graph_returns_empty(self):
        graph = DirectedAttackGraph(scenario_id="disconnected")
        graph.add_node(Node(id="user:UserA", type="user", name="UserA"))
        graph.add_node(Node(id="resource:BucketA", type="resource", name="BucketA"))
        paths = self.finder.find_paths(graph)
        self.assertEqual(paths, [])


if __name__ == "__main__":
    unittest.main()


class TestExplicitDeny(unittest.TestCase):
    """Explicit Deny overrides Allow during path discovery."""

    def _paths(self, permissions, trust_statements=None):
        trust = trust_statements or [{"Effect": "Allow", "Principal": {"AWS": "U"}, "Action": "sts:AssumeRole"}]
        raw = {
            "scenario_id": "deny",
            "users": [{"name": "U"}],
            "roles": [{"name": "R", "trust_policy": {"Statement": trust}, "permissions": permissions}],
            "resources": [{"name": "B", "type": "s3", "arn": "arn:aws:s3:::b"}],
        }
        return PathFinder().find_paths(build_attack_graph(normalize_scenario(raw)))

    def test_matching_deny_blocks_allow(self):
        paths = self._paths([
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        ])
        self.assertEqual(paths, [])

    def test_deny_of_one_action_keeps_rest_of_wildcard_allow(self):
        paths = self._paths([
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::b/*"},
        ])
        self.assertTrue(paths)

    def test_deny_on_narrower_resource_does_not_block(self):
        paths = self._paths([
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/secret/*"},
        ])
        self.assertTrue(paths)

    def test_trust_policy_deny_blocks_assume_role(self):
        paths = self._paths(
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
            trust_statements=[
                {"Effect": "Allow", "Principal": {"AWS": "U"}, "Action": "sts:AssumeRole"},
                {"Effect": "Deny", "Principal": {"AWS": "U"}, "Action": "sts:AssumeRole"},
            ],
        )
        self.assertEqual(paths, [])

    def test_conditional_deny_is_not_assumed_to_apply(self):
        paths = self._paths([
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        ])
        self.assertTrue(paths)
