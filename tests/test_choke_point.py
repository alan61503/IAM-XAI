"""Unit tests for Phase 8: Choke Point Detection."""

import json
from pathlib import Path
import tempfile
import unittest

from choke_point.choke_finder import identify_path_choke_point, identify_scenario_choke_points
from choke_point.main import main as cli_main


class TestChokePointDetection(unittest.TestCase):
    def setUp(self):
        self.sample_path = {
            "path_id": "test_path_001",
            "scenario_id": "test_scenario",
            "source": "user:InitialUser",
            "target": "resource:ProductionDataBucket",
            "nodes": [
                "user:InitialUser",
                "role:IntermediateRoleA",
                "role:TargetRoleB",
                "resource:ProductionDataBucket",
            ],
            "edges": [
                {
                    "source": "user:InitialUser",
                    "target": "role:IntermediateRoleA",
                    "edge_type": "CAN_ASSUME",
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "resources": [],
                    "metadata": {"origin": "trust_policy", "principal_type": "internal"},
                },
                {
                    "source": "role:IntermediateRoleA",
                    "target": "role:TargetRoleB",
                    "edge_type": "CAN_ASSUME",
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "resources": [],
                    "metadata": {"origin": "permission"},
                },
                {
                    "source": "role:TargetRoleB",
                    "target": "resource:ProductionDataBucket",
                    "edge_type": "CAN_ACCESS",
                    "effect": "Allow",
                    "actions": ["s3:GetObject"],
                    "resources": ["arn:aws:s3:::production-data/*"],
                    "metadata": {"origin": "permission"},
                },
            ],
            "hop_count": 3,
            "conditional": False,
        }

        self.sample_shap = {
            "path_id": "test_path_001",
            "prediction": "HIGH",
            "top_factors": [
                {"feature": "assume_role", "impact": 0.25},
                {"feature": "role_count", "impact": 0.18},
                {"feature": "sensitive_target", "impact": 0.12},
            ],
        }

    def test_identify_path_choke_point(self):
        result = identify_path_choke_point(self.sample_path, self.sample_shap)
        self.assertIsNotNone(result)
        self.assertIn("choke_point_id", result)
        self.assertEqual(result["source"], "user:InitialUser")
        self.assertEqual(result["target"], "role:IntermediateRoleA")
        self.assertEqual(result["edge_type"], "CAN_ASSUME")
        self.assertGreater(result["choke_score"], 0.0)

    def test_identify_scenario_choke_points(self):
        paths = [self.sample_path]
        explanations = [self.sample_shap]
        predictions = [{"path_id": "test_path_001", "predicted_label": "HIGH", "predicted_score": 0.85}]

        choke_points = identify_scenario_choke_points(paths, explanations, predictions)
        self.assertEqual(len(choke_points), 3)
        top = choke_points[0]
        self.assertEqual(top["paths_blocked"], 1)
        self.assertGreater(top["choke_score"], 0.0)

    def test_cli_execution(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp_in, \
             tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp_out:
            tmp_in_path = Path(tmp_in.name)
            tmp_out_path = Path(tmp_out.name)

        try:
            tmp_in_path.write_text(json.dumps({"paths": [self.sample_path]}), encoding="utf-8")
            ret = cli_main([str(tmp_in_path), "--output", str(tmp_out_path)])
            self.assertEqual(ret, 0)

            data = json.loads(tmp_out_path.read_text(encoding="utf-8"))
            self.assertIn("choke_points", data)
            self.assertEqual(len(data["choke_points"]), 3)
        finally:
            tmp_in_path.unlink(missing_ok=True)
            tmp_out_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
