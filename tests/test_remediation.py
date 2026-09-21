"""Unit tests for Phase 9: Remediation Engine."""

import json
from pathlib import Path
import tempfile
import unittest

from remediation.diff_generator import generate_policy_diff, generate_remediation_playbook
from remediation.main import main as cli_main
from remediation.policy_remediator import remediate_choke_point
from remediation.simulator import verify_remediation


class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        self.sample_scenario = {
            "scenario_id": "scenario_009",
            "users": [{"name": "InitialUser"}],
            "roles": [
                {
                    "name": "IntermediateRoleA",
                    "trust_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "InitialUser"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "permissions": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::123456789012:role/TargetRoleB",
                        }
                    ],
                },
                {
                    "name": "TargetRoleB",
                    "trust_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "IntermediateRoleA"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "permissions": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::critical-production-data/*",
                        }
                    ],
                },
            ],
            "resources": [
                {
                    "name": "ProductionDataBucket",
                    "type": "s3",
                    "arn": "arn:aws:s3:::critical-production-data",
                }
            ],
        }

        self.sample_choke = {
            "choke_point_id": "cp_scenario_001",
            "source": "user:InitialUser",
            "target": "role:IntermediateRoleA",
            "edge_type": "CAN_ASSUME",
            "actions": ["sts:AssumeRole"],
            "paths_blocked": 1,
        }

    def test_remediate_choke_point_revoke_trust(self):
        remediated, summary = remediate_choke_point(self.sample_scenario, self.sample_choke)
        self.assertTrue(summary["patch_applied"])
        self.assertEqual(summary["patch_type"], "REVOKE_TRUST_POLICY_STATEMENT")

        # Verify trust statement was removed from IntermediateRoleA
        role_a = next(r for r in remediated["roles"] if r["name"] == "IntermediateRoleA")
        self.assertEqual(len(role_a["trust_policy"]["Statement"]), 0)

    def test_policy_diff(self):
        remediated, _ = remediate_choke_point(self.sample_scenario, self.sample_choke)
        diff = generate_policy_diff(self.sample_scenario, remediated)
        self.assertIn("role:IntermediateRoleA (trust_policy)", diff["entities_modified"])
        self.assertEqual(len(diff["role_trust_policy_diffs"]), 1)

    def test_verify_remediation(self):
        remediated, _ = remediate_choke_point(self.sample_scenario, self.sample_choke)
        verification = verify_remediation(self.sample_scenario, remediated)
        self.assertTrue(verification["is_verified"])
        self.assertGreater(verification["before_paths_count"], verification["after_paths_count"])

    def test_cli_execution(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp_scen, \
             tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp_choke, \
             tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp_out:
            scen_path = Path(tmp_scen.name)
            choke_path = Path(tmp_choke.name)
            out_path = Path(tmp_out.name)

        try:
            scen_path.write_text(json.dumps(self.sample_scenario), encoding="utf-8")
            choke_path.write_text(json.dumps({"choke_points": [self.sample_choke]}), encoding="utf-8")

            ret = cli_main([str(scen_path), str(choke_path), "--output", str(out_path)])
            self.assertEqual(ret, 0)

            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn("remediation_summary", data)
            self.assertIn("verification", data)
            self.assertTrue(data["verification"]["is_verified"])
        finally:
            scen_path.unlink(missing_ok=True)
            choke_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
