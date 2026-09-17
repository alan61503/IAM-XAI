"""Tests for the Phase 4 feature extractor.

The tests cover all required feature categories, edge‑cases and the
behavioural guarantees described in the user request.
"""

import unittest
from typing import Dict, List

from features.feature_extractor import extract_features


def _make_path(
    *,
    path_id: str = "test_path",
    scenario_id: str = "test_scenario",
    source: str = "user:U1",
    target: str = "resource:R1",
    nodes: List[str] = None,
    edges: List[Dict] = None,
    hop_count: int = None,
    conditional: bool = False,
    target_metadata: Dict = None,
) -> Dict:
    """Utility to build a minimal path dict for the extractor tests."""
    if nodes is None:
        nodes = [source, target]
    if edges is None:
        edges = []
    if hop_count is None:
        hop_count = len(edges)
    return {
        "scenario_id": scenario_id,
        "path_id": path_id,
        "source": source,
        "target": target,
        "nodes": nodes,
        "edges": edges,
        "hop_count": hop_count,
        "conditional": conditional,
        "target_metadata": target_metadata or {},
    }


class TestFeatureExtractor(unittest.TestCase):
    def test_basic_structure_counts(self):
        path = _make_path(
            nodes=["user:U1", "role:R1", "resource:Res"],
            edges=[
                {
                    "source": "user:U1",
                    "target": "role:R1",
                    "edge_type": "CAN_ASSUME",
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "resources": [],
                    "conditions": {},
                    "metadata": {},
                }
            ],
        )
        rec = extract_features(path)["features"]
        self.assertEqual(rec["hop_count"], 1)
        self.assertEqual(rec["node_count"], 3)
        self.assertEqual(rec["unique_node_count"], 3)
        self.assertEqual(rec["user_count"], 1)
        self.assertEqual(rec["role_count"], 1)
        self.assertEqual(rec["resource_count"], 1)

    def test_edge_type_counts_and_flags(self):
        edges = [
            {"source": "u", "target": "r1", "edge_type": "CAN_ASSUME", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
            {"source": "r1", "target": "r2", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
            {"source": "r2", "target": "res", "edge_type": "CAN_PASS_ROLE", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
        ]
        path = _make_path(nodes=["user:u", "role:r1", "role:r2", "resource:res"], edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["assume_count"], 1)
        self.assertEqual(rec["access_count"], 1)
        self.assertEqual(rec["modify_count"], 0)
        self.assertEqual(rec["passrole_count"], 1)
        self.assertEqual(rec["trust_edge_count"], 1)  # only CAN_ASSUME
        self.assertEqual(rec["has_assume"], 1)
        self.assertEqual(rec["has_access"], 1)
        self.assertEqual(rec["has_modify"], 0)
        self.assertEqual(rec["has_passrole"], 1)

    def test_permission_breadth_and_wildcards(self):
        edges = [
            {
                "source": "u",
                "target": "r",
                "edge_type": "CAN_ACCESS",
                "effect": "Allow",
                "actions": ["s3:GetObject", "s3:*"],
                "resources": ["arn:aws:s3:::bucket/*", "*"],
                "conditions": {},
                "metadata": {},
            }
        ]
        path = _make_path(nodes=["user:u", "resource:res"], edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["action_count"], 2)
        self.assertEqual(rec["unique_action_count"], 2)
        self.assertEqual(rec["wildcard_action_count"], 1)  # s3:*
        self.assertEqual(rec["resource_pattern_count"], 2)
        self.assertEqual(rec["unique_resource_pattern_count"], 2)
        self.assertEqual(rec["wildcard_resource_count"], 1)  # *
        self.assertEqual(rec["has_wildcard_action"], 1)
        self.assertEqual(rec["has_wildcard_resource"], 1)

    def test_broad_permission_metadata(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {"broad_permission": True}},
            {"source": "r", "target": "res", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["broad_permission_edge_count"], 1)
        self.assertEqual(rec["has_broad_permission"], 1)

    def test_principal_metadata_counts(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ASSUME", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {"principal_type": "external"}},
            {"source": "r", "target": "r2", "edge_type": "CAN_ASSUME", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {"principal_type": "service"}},
            {"source": "r2", "target": "res", "edge_type": "CAN_ASSUME", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {"principal_type": "wildcard"}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["external_principal_count"], 1)
        self.assertEqual(rec["service_principal_count"], 1)
        self.assertEqual(rec["wildcard_principal_count"], 1)
        self.assertEqual(rec["has_external_principal"], 1)
        self.assertEqual(rec["has_service_principal"], 1)
        self.assertEqual(rec["has_wildcard_principal"], 1)

    def test_condition_counts_distinct(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {"StringEquals": {"aws:username": "bob"}}, "metadata": {}},
            {"source": "r", "target": "res", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {"StringEquals": {"aws:username": "alice"}, "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, "metadata": {}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["conditional_edge_count"], 2)
        self.assertEqual(rec["has_conditions"], 1)
        self.assertEqual(rec["condition_operator_count"], 2)  # StringEquals, IpAddress
        self.assertEqual(rec["condition_key_count"], 2)  # aws:username, aws:SourceIp

    def test_effect_counts(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
            {"source": "r", "target": "res", "edge_type": "CAN_ACCESS", "effect": "Deny", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["allow_edge_count"], 1)
        self.assertEqual(rec["deny_edge_count"], 1)

    def test_target_features_and_optional_metadata(self):
        path = _make_path(
            target="resource:MyBucket",
            target_metadata={"sensitive": True, "criticality": "high"},
        )
        rec = extract_features(path)["features"]
        self.assertEqual(rec["target_type"], "resource")
        self.assertEqual(rec["target_is_resource"], 1)
        self.assertEqual(rec["target_is_role"], 0)
        self.assertEqual(rec["target_is_user"], 0)
        self.assertTrue(rec["target_sensitive"])
        self.assertEqual(rec["target_criticality"], "high")

    def test_ratio_safe_division(self):
        # zero-hop path – ratios must be 0.0 and not raise
        path = _make_path(nodes=["user:u"], edges=[], hop_count=0)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["role_hop_ratio"], 0.0)
        self.assertEqual(rec["assume_ratio"], 0.0)
        self.assertEqual(rec["access_ratio"], 0.0)
        self.assertEqual(rec["modify_ratio"], 0.0)
        self.assertEqual(rec["passrole_ratio"], 0.0)

    def test_distinct_service_count(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ACCESS", "effect": "Allow", "actions": ["s3:GetObject", "sts:AssumeRole"], "resources": [], "conditions": {}, "metadata": {}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["distinct_service_count"], 2)

    def test_missing_principal_metadata_defaults(self):
        edges = [
            {"source": "u", "target": "r", "edge_type": "CAN_ASSUME", "effect": "Allow", "actions": [], "resources": [], "conditions": {}, "metadata": {}},
        ]
        path = _make_path(edges=edges)
        rec = extract_features(path)["features"]
        self.assertEqual(rec["external_principal_count"], 0)
        self.assertEqual(rec["service_principal_count"], 0)
        self.assertEqual(rec["wildcard_principal_count"], 0)
        self.assertEqual(rec["has_external_principal"], 0)
        self.assertEqual(rec["has_service_principal"], 0)
        self.assertEqual(rec["has_wildcard_principal"], 0)

    def test_deterministic_ordering(self):
        from features.feature_schema import FEATURE_NAMES
        path = _make_path()
        rec = extract_features(path)["features"]
        ordered_keys = list(rec.keys())
        self.assertEqual(ordered_keys, FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
