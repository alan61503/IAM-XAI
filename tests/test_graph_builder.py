"""Unit and integration tests for graph_builder across all scenarios."""

import unittest
from pathlib import Path

from graph.action_mapper import (
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_MODIFY,
)
from graph.graph_builder import GraphBuilder, build_attack_graph
from parser.normalizer import normalize_scenario_file


class TestGraphBuilder(unittest.TestCase):
    """Test attack graph construction from Phase 1 normalized scenarios."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "data" / "scenarios"
        self.builder = GraphBuilder()

    def _load_scenario_graph(self, filename: str):
        normalized = normalize_scenario_file(self.scenarios_dir / filename)
        return self.builder.build_graph(normalized)

    def test_scenario_001_basic_graph(self):
        # 1 user, 1 role, 1 trust, 1 permission
        graph = self._load_scenario_graph("scenario_001.json")

        self.assertEqual(graph.scenario_id, "scenario_001")
        self.assertTrue(graph.has_node("user:UserA"))
        self.assertTrue(graph.has_node("role:RoleA"))
        self.assertTrue(graph.has_node("resource:ExampleBucket"))

        # Check CAN_ASSUME edge
        assume_edges = graph.get_edges(
            source="user:UserA", target="role:RoleA", edge_type=EDGE_TYPE_ASSUME
        )
        self.assertEqual(len(assume_edges), 1)
        self.assertEqual(assume_edges[0].effect, "Allow")
        self.assertEqual(assume_edges[0].actions, ["sts:AssumeRole"])

        # Check CAN_ACCESS edge
        access_edges = graph.get_edges(
            source="role:RoleA",
            target="resource:ExampleBucket",
            edge_type=EDGE_TYPE_ACCESS,
        )
        self.assertEqual(len(access_edges), 1)
        self.assertEqual(access_edges[0].effect, "Allow")
        self.assertEqual(access_edges[0].actions, ["s3:GetObject"])

    def test_scenario_002_multiple_actions(self):
        # Role with s3:GetObject, s3:PutObject, s3:ListBucket
        graph = self._load_scenario_graph("scenario_002.json")
        access_edges = graph.get_edges(
            source="role:DevRole",
            target="resource:DevBucket",
            edge_type=EDGE_TYPE_ACCESS,
        )
        modify_edges = graph.get_edges(
            source="role:DevRole",
            target="resource:DevBucket",
            edge_type=EDGE_TYPE_MODIFY,
        )
        self.assertEqual(len(access_edges), 1)
        self.assertEqual(len(modify_edges), 1)
        self.assertEqual(access_edges[0].actions, ["s3:GetObject", "s3:ListBucket"])
        self.assertEqual(modify_edges[0].actions, ["s3:PutObject"])

    def test_scenario_003_multiple_resources(self):
        # AuditorRole granting access across 3 buckets
        graph = self._load_scenario_graph("scenario_003.json")
        auditor_edges = graph.get_edges(
            source="role:AuditorRole", edge_type=EDGE_TYPE_ACCESS
        )
        target_names = {graph.get_node(e.target).name for e in auditor_edges}
        self.assertEqual(
            target_names,
            {"FinanceBucket", "HRBucket", "ComplianceBucket"},
        )

    def test_scenario_004_multiple_statements(self):
        # Multiple statements in trust policy (OpsUser + ec2 service) and permissions (S3 + DynamoDB)
        graph = self._load_scenario_graph("scenario_004.json")

        # Two distinct principals assuming MultiStatementRole
        assume_edges = graph.get_edges(
            target="role:MultiStatementRole", edge_type=EDGE_TYPE_ASSUME
        )
        sources = {e.source for e in assume_edges}
        self.assertEqual(sources, {"user:OpsUser", "service:ec2.amazonaws.com"})

        # MultiStatementRole accessing AppDataBucket and AppTable
        access_edges = graph.get_edges(
            source="role:MultiStatementRole", edge_type=EDGE_TYPE_ACCESS
        )
        targets = {e.target for e in access_edges}
        self.assertEqual(targets, {"resource:AppDataBucket", "resource:AppTable"})

    def test_scenario_005_explicit_deny(self):
        # Role with Allow on s3:* and explicit Deny on s3:DeleteObject
        graph = self._load_scenario_graph("scenario_005.json")

        allow_edges = graph.get_edges(
            source="role:RestrictedRole",
            target="resource:GeneralBucket",
            effect="Allow",
        )
        deny_edges = graph.get_edges(
            source="role:RestrictedRole",
            target="resource:GeneralBucket",
            effect="Deny",
        )
        self.assertTrue(len(allow_edges) > 0)
        self.assertEqual(len(deny_edges), 1)
        self.assertEqual(deny_edges[0].effect, "Deny")
        self.assertEqual(deny_edges[0].edge_type, EDGE_TYPE_MODIFY)
        self.assertEqual(deny_edges[0].actions, ["s3:DeleteObject"])

    def test_scenario_006_wildcards(self):
        # Full wildcard action '*' and 's3:*' on resource '*'
        graph = self._load_scenario_graph("scenario_006.json")
        # Trust policy with AWS: "*"
        wildcard_assume = graph.get_edges(
            source="principal:*", target="role:AdminRole", edge_type=EDGE_TYPE_ASSUME
        )
        self.assertEqual(len(wildcard_assume), 1)

        # AdminRole edges to AllResources
        admin_edges = graph.get_edges(source="role:AdminRole", target="resource:AllResources")
        edge_types = {e.edge_type for e in admin_edges}
        self.assertIn(EDGE_TYPE_ACCESS, edge_types)
        self.assertIn(EDGE_TYPE_MODIFY, edge_types)

    def test_scenario_007_multiple_principals(self):
        # UserAlpha, UserBeta, lambda service assuming SharedRole
        graph = self._load_scenario_graph("scenario_007.json")
        shared_assume = graph.get_edges(target="role:SharedRole", edge_type=EDGE_TYPE_ASSUME)
        self.assertEqual(len(shared_assume), 3)
        sources = {e.source for e in shared_assume}
        self.assertEqual(sources, {"user:UserAlpha", "user:UserBeta", "service:lambda.amazonaws.com"})

    def test_scenario_008_conditions_preserved(self):
        # MFA on trust policy, IP on permission
        graph = self._load_scenario_graph("scenario_008.json")

        assume_edge = graph.get_edges(
            source="user:SecuredUser", target="role:SecuredRole"
        )[0]
        self.assertEqual(
            assume_edge.conditions,
            {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )

        access_edge = graph.get_edges(
            source="role:SecuredRole", target="resource:DatabaseCredentials"
        )[0]
        self.assertEqual(
            access_edge.conditions,
            {"IpAddress": {"aws:SourceIp": "10.0.0.0/16"}},
        )

    def test_scenario_009_role_chaining(self):
        # User -> RoleA -> RoleB -> ProductionDataBucket
        graph = self._load_scenario_graph("scenario_009.json")

        # InitialUser -> IntermediateRoleA
        edge_1 = graph.get_edges(
            source="user:InitialUser",
            target="role:IntermediateRoleA",
            edge_type=EDGE_TYPE_ASSUME,
        )
        self.assertEqual(len(edge_1), 1)

        # IntermediateRoleA -> TargetRoleB (via trust and permission)
        edge_2 = graph.get_edges(
            source="role:IntermediateRoleA",
            target="role:TargetRoleB",
            edge_type=EDGE_TYPE_ASSUME,
        )
        self.assertTrue(len(edge_2) >= 1)

        # TargetRoleB -> ProductionDataBucket
        edge_3 = graph.get_edges(
            source="role:TargetRoleB",
            target="resource:ProductionDataBucket",
            edge_type=EDGE_TYPE_ACCESS,
        )
        self.assertEqual(len(edge_3), 1)

    # Edge cases and robustness tests
    def test_nonexistent_reference_synthesis(self):
        # Reference to a resource not explicitly declared in entities
        normalized = {
            "scenario_id": "undeclared_ref_test",
            "entities": [{"type": "role", "name": "IsolatedRole"}],
            "permissions": [
                {
                    "source": "IsolatedRole",
                    "effect": "Allow",
                    "actions": ["s3:GetObject"],
                    "resources": ["arn:aws:s3:::external-bucket/*"],
                }
            ],
            "trust_relationships": [],
        }
        graph = self.builder.build_graph(normalized)
        # Should synthesize target resource node
        self.assertTrue(graph.has_node("resource:arn:aws:s3:::external-bucket/*"))
        edges = graph.get_edges(source="role:IsolatedRole")
        self.assertEqual(len(edges), 1)

    def test_duplicate_entities_handling(self):
        normalized = {
            "scenario_id": "dup_entity_test",
            "entities": [
                {"type": "user", "name": "UserDup"},
                {"type": "user", "name": "UserDup"},
            ],
            "permissions": [],
            "trust_relationships": [],
        }
        graph = self.builder.build_graph(normalized)
        self.assertEqual(len(graph.nodes), 1)

    def test_duplicate_relationships_handling(self):
        normalized = {
            "scenario_id": "dup_rel_test",
            "entities": [
                {"type": "user", "name": "UserA"},
                {"type": "role", "name": "RoleA"},
            ],
            "permissions": [],
            "trust_relationships": [
                {
                    "source": "UserA",
                    "target": "RoleA",
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "conditions": {},
                },
                {
                    "source": "UserA",
                    "target": "RoleA",
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "conditions": {},
                },
            ],
        }
        graph = self.builder.build_graph(normalized)
        self.assertEqual(len(graph.edges), 1)

    def test_malformed_normalized_input_raises_error(self):
        with self.assertRaises(ValueError):
            self.builder.build_graph("not-a-dict")

    # Tests for Semantic Corrections
    def test_pass_role_creates_can_pass_role_and_not_can_assume(self):
        """Verify iam:PassRole creates CAN_PASS_ROLE and does NOT create CAN_ASSUME."""
        normalized = {
            "scenario_id": "pass_role_test",
            "entities": [
                {"type": "role", "name": "ServiceRole"},
                {"type": "role", "name": "TargetWorkerRole", "arn": "arn:aws:iam::123:role/TargetWorkerRole"},
            ],
            "permissions": [
                {
                    "source": "ServiceRole",
                    "effect": "Allow",
                    "actions": ["iam:PassRole"],
                    "resources": ["arn:aws:iam::123:role/TargetWorkerRole"],
                }
            ],
            "trust_relationships": [],
        }
        graph = self.builder.build_graph(normalized)

        # 1. PassRole creates CAN_PASS_ROLE
        pass_role_edges = graph.get_edges(
            source="role:ServiceRole",
            target="role:TargetWorkerRole",
            edge_type="CAN_PASS_ROLE",
        )
        self.assertEqual(len(pass_role_edges), 1)
        self.assertEqual(pass_role_edges[0].actions, ["iam:PassRole"])

        # 2. PassRole does NOT create CAN_ASSUME
        assume_edges = graph.get_edges(
            source="role:ServiceRole",
            target="role:TargetWorkerRole",
            edge_type=EDGE_TYPE_ASSUME,
        )
        self.assertEqual(len(assume_edges), 0)

        # 3. A role with PassRole alone does not automatically gain an AssumeRole edge
        all_assume = graph.get_edges(edge_type=EDGE_TYPE_ASSUME)
        self.assertEqual(len(all_assume), 0)

    def test_wildcard_action_star_does_not_create_assume_or_pass_role(self):
        """Verify Action: '*' does not blindly create CAN_ASSUME or CAN_PASS_ROLE."""
        normalized = {
            "scenario_id": "wildcard_conservative_test",
            "entities": [
                {"type": "role", "name": "PowerRole"},
                {"type": "role", "name": "OtherRole", "arn": "arn:aws:iam::123:role/OtherRole"},
                {"type": "resource", "name": "DataBucket", "arn": "arn:aws:s3:::data-bucket", "resource_type": "s3"},
            ],
            "permissions": [
                {
                    "source": "PowerRole",
                    "effect": "Allow",
                    "actions": ["*"],
                    "resources": ["*"],
                }
            ],
            "trust_relationships": [],
        }
        graph = self.builder.build_graph(normalized)

        # PowerRole should NOT gain CAN_ASSUME or CAN_PASS_ROLE to OtherRole merely from Action: "*"
        assume_to_other = graph.get_edges(
            source="role:PowerRole",
            target="role:OtherRole",
            edge_type=EDGE_TYPE_ASSUME,
        )
        self.assertEqual(len(assume_to_other), 0)

        pass_to_other = graph.get_edges(
            source="role:PowerRole",
            target="role:OtherRole",
            edge_type="CAN_PASS_ROLE",
        )
        self.assertEqual(len(pass_to_other), 0)

        # PowerRole should have CAN_ACCESS and CAN_MODIFY to DataBucket with broad metadata
        bucket_edges = graph.get_edges(
            source="role:PowerRole",
            target="resource:DataBucket",
        )
        edge_types = {e.edge_type for e in bucket_edges}
        self.assertEqual(edge_types, {EDGE_TYPE_ACCESS, EDGE_TYPE_MODIFY})

        for edge in bucket_edges:
            self.assertEqual(edge.actions, ["*"])
            self.assertTrue(edge.metadata.get("broad_permission"))
            self.assertEqual(edge.metadata.get("action_scope"), "wildcard")

    def test_declared_vs_synthesized_resource_provenance(self):
        """Verify declared vs synthesized resources are explicitly distinguishable via metadata."""
        normalized = {
            "scenario_id": "provenance_test",
            "entities": [
                {"type": "role", "name": "AppRole"},
                {"type": "resource", "name": "DeclaredBucket", "arn": "arn:aws:s3:::declared-bucket"},
            ],
            "permissions": [
                {
                    "source": "AppRole",
                    "effect": "Allow",
                    "actions": ["s3:GetObject"],
                    "resources": [
                        "arn:aws:s3:::declared-bucket/*",
                        "arn:aws:s3:::undeclared-external-bucket/*",
                    ],
                }
            ],
            "trust_relationships": [],
        }
        graph = self.builder.build_graph(normalized)

        declared_node = graph.get_node("resource:DeclaredBucket")
        self.assertIsNotNone(declared_node)
        self.assertFalse(declared_node.metadata.get("synthetic", True))

        synth_node = graph.get_node("resource:arn:aws:s3:::undeclared-external-bucket/*")
        self.assertIsNotNone(synth_node)
        self.assertTrue(synth_node.metadata.get("synthetic"))
        self.assertEqual(synth_node.metadata.get("source"), "permission_resource")


if __name__ == "__main__":
    unittest.main()
