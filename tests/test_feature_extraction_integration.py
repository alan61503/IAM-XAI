"""Integration test for Phase 4 feature extraction using real Scenario 009 data.

The test loads the Phase‑3 paths file for scenario 009 that is part of the
project's ``output`` directory, runs the extractor on each path and asserts
several known properties of the main multi‑hop path.
"""

import unittest
import json
from pathlib import Path

from features.feature_extractor import extract_features

class TestFeatureExtractionIntegrationScenario009(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load the Phase‑3 paths JSON produced by Phase 3
        cls.paths_file = Path(__file__).parents[1] / "output" / "scenario_009_paths.json"
        data = json.loads(cls.paths_file.read_text())
        # The file contains a top‑level dict with a ``paths`` key
        cls.paths = data["paths"] if isinstance(data, dict) and "paths" in data else data

    def test_multi_hop_path_features(self):
        # Find the path that matches the expected multi‑hop chain
        target_path = None
        for p in self.paths:
            if p.get("path_id") == "scenario_009_path_001":
                target_path = p
                break
        self.assertIsNotNone(target_path, "Expected multi‑hop path not found in scenario_009_paths.json")

        rec = extract_features(target_path)["features"]

        # Known structure: InitialUser -> IntermediateRoleA -> TargetRoleB -> ProductionDataBucket
        self.assertEqual(rec["hop_count"], 3)
        self.assertEqual(rec["node_count"], 4)
        self.assertEqual(rec["role_count"], 2)
        self.assertEqual(rec["user_count"], 1)
        self.assertEqual(rec["resource_count"], 1)

        # Edge‑type counts – the path uses CAN_ASSUME, CAN_ASSUME, CAN_ACCESS
        self.assertEqual(rec["assume_count"], 2)
        self.assertEqual(rec["access_count"], 1)
        self.assertEqual(rec["modify_count"], 0)
        self.assertEqual(rec["passrole_count"], 0)
        self.assertEqual(rec["trust_edge_count"], 2)  # only CAN_ASSUME edges

        # Verify distinct_service_count includes at least "sts" and the service for the final access
        self.assertGreaterEqual(rec["distinct_service_count"], 2)

        # Ensure the schema does NOT contain the removed feature
        self.assertNotIn("distinct_action_family_count", rec)

        # Verify ratios are computed safely
        self.assertAlmostEqual(rec["assume_ratio"], 2/3)
        self.assertAlmostEqual(rec["access_ratio"], 1/3)
        self.assertEqual(rec["modify_ratio"], 0.0)
        self.assertEqual(rec["passrole_ratio"], 0.0)

        # Confirm target feature flags
        self.assertEqual(rec["target_type"], "resource")
        self.assertEqual(rec["target_is_resource"], 1)
        self.assertEqual(rec["target_is_role"], 0)
        self.assertEqual(rec["target_is_user"], 0)

if __name__ == "__main__":
    unittest.main()
