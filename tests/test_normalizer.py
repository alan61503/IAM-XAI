"""Unit and integration tests for normalizer module and CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from parser.policy_parser import IAMValidationError
from parser.normalizer import (
    normalize_scenario,
    normalize_scenario_file,
)
from parser.main import main as cli_main


class TestNormalizer(unittest.TestCase):
    """Test scenario normalization and CLI execution."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "data" / "scenarios"

    def test_normalize_scenario_001_basic(self):
        scenario_path = self.scenarios_dir / "scenario_001.json"
        res = normalize_scenario_file(scenario_path)

        self.assertEqual(res["scenario_id"], "scenario_001")
        self.assertEqual(len(res["entities"]), 3)
        entity_types = {e["type"] for e in res["entities"]}
        entity_names = {e["name"] for e in res["entities"]}
        self.assertEqual(entity_types, {"user", "role", "resource"})
        self.assertEqual(entity_names, {"UserA", "RoleA", "ExampleBucket"})

        # Permissions check
        self.assertEqual(len(res["permissions"]), 1)
        perm = res["permissions"][0]
        self.assertEqual(perm["source"], "RoleA")
        self.assertEqual(perm["effect"], "Allow")
        self.assertEqual(perm["actions"], ["s3:GetObject"])
        self.assertEqual(perm["resources"], ["arn:aws:s3:::example-bucket/*"])
        self.assertEqual(perm["conditions"], {})

        # Trust relationships check
        self.assertEqual(len(res["trust_relationships"]), 1)
        trust = res["trust_relationships"][0]
        self.assertEqual(trust["source"], "UserA")
        self.assertEqual(trust["target"], "RoleA")
        self.assertEqual(trust["effect"], "Allow")
        self.assertEqual(trust["actions"], ["sts:AssumeRole"])

    def test_normalize_scenario_002_multiple_actions(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_002.json")
        self.assertEqual(res["scenario_id"], "scenario_002")
        perm = res["permissions"][0]
        self.assertEqual(len(perm["actions"]), 3)
        self.assertEqual(perm["actions"], ["s3:GetObject", "s3:PutObject", "s3:ListBucket"])

    def test_normalize_scenario_003_multiple_resources(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_003.json")
        self.assertEqual(res["scenario_id"], "scenario_003")
        perm = res["permissions"][0]
        self.assertEqual(len(perm["resources"]), 3)
        self.assertIn("arn:aws:s3:::finance-bucket/*", perm["resources"])
        self.assertIn("arn:aws:s3:::hr-bucket/*", perm["resources"])
        self.assertIn("arn:aws:s3:::compliance-bucket/*", perm["resources"])

    def test_normalize_scenario_004_multiple_statements(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_004.json")
        self.assertEqual(res["scenario_id"], "scenario_004")
        self.assertEqual(len(res["permissions"]), 2)
        self.assertEqual(len(res["trust_relationships"]), 2)
        trust_sources = {t["source"] for t in res["trust_relationships"]}
        self.assertEqual(trust_sources, {"OpsUser", "ec2.amazonaws.com"})

    def test_normalize_scenario_005_deny(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_005.json")
        self.assertEqual(res["scenario_id"], "scenario_005")
        effects = [p["effect"] for p in res["permissions"]]
        self.assertIn("Allow", effects)
        self.assertIn("Deny", effects)

    def test_normalize_scenario_006_wildcards(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_006.json")
        self.assertEqual(res["scenario_id"], "scenario_006")
        self.assertEqual(res["permissions"][0]["actions"], ["*"])
        self.assertEqual(res["permissions"][0]["resources"], ["*"])
        self.assertEqual(res["permissions"][1]["actions"], ["s3:*"])
        self.assertEqual(res["permissions"][1]["resources"], ["arn:aws:s3:::*"])
        self.assertEqual(res["trust_relationships"][0]["source"], "*")

    def test_normalize_scenario_007_multiple_principals(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_007.json")
        self.assertEqual(res["scenario_id"], "scenario_007")
        trust_sources = [t["source"] for t in res["trust_relationships"]]
        self.assertEqual(len(trust_sources), 3)
        self.assertIn("UserAlpha", trust_sources)
        self.assertIn("UserBeta", trust_sources)
        self.assertIn("lambda.amazonaws.com", trust_sources)

    def test_normalize_scenario_008_conditions(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_008.json")
        self.assertEqual(res["scenario_id"], "scenario_008")
        trust_cond = res["trust_relationships"][0]["conditions"]
        self.assertIn("Bool", trust_cond)
        self.assertEqual(trust_cond["Bool"]["aws:MultiFactorAuthPresent"], "true")

        perm_cond = res["permissions"][0]["conditions"]
        self.assertIn("IpAddress", perm_cond)
        self.assertEqual(perm_cond["IpAddress"]["aws:SourceIp"], "10.0.0.0/16")

    def test_normalize_scenario_009_role_chaining(self):
        res = normalize_scenario_file(self.scenarios_dir / "scenario_009.json")
        self.assertEqual(res["scenario_id"], "scenario_009")

        # Check trust relationships: InitialUser -> RoleA, IntermediateRoleA -> RoleB
        trust_pairs = {(t["source"], t["target"]) for t in res["trust_relationships"]}
        self.assertIn(("InitialUser", "IntermediateRoleA"), trust_pairs)
        self.assertIn(("IntermediateRoleA", "TargetRoleB"), trust_pairs)

        # Check permission of RoleA to assume RoleB
        role_a_perms = [p for p in res["permissions"] if p["source"] == "IntermediateRoleA"]
        self.assertEqual(len(role_a_perms), 1)
        self.assertEqual(role_a_perms[0]["actions"], ["sts:AssumeRole"])
        self.assertIn("arn:aws:iam::123456789012:role/TargetRoleB", role_a_perms[0]["resources"])

    def test_missing_scenario_id_raises_error(self):
        data = {"users": [], "roles": []}
        with self.assertRaises(IAMValidationError) as ctx:
            normalize_scenario(data)
        self.assertIn("scenario_id", str(ctx.exception))

    def test_nonexistent_file_raises_error(self):
        with self.assertRaises(IAMValidationError) as ctx:
            normalize_scenario_file("non_existent_file.json")
        self.assertIn("not found", str(ctx.exception))

    def test_invalid_json_file_raises_error(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            tmp.write("{ invalid json")
            tmp_path = tmp.name
        try:
            with self.assertRaises(IAMValidationError) as ctx:
                normalize_scenario_file(tmp_path)
            self.assertIn("Invalid JSON syntax", str(ctx.exception))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_invalid_entity_structure_raises_error(self):
        data = {
            "scenario_id": "test_err",
            "users": [{"invalid_key": "UserX"}],
        }
        with self.assertRaises(IAMValidationError) as ctx:
            normalize_scenario(data)
        self.assertIn("must have a non-empty string 'name'", str(ctx.exception))

    def test_cli_execution_with_output_argument(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            out_path = tmp.name

        try:
            scenario_1_path = str(self.scenarios_dir / "scenario_001.json")
            ret_code = cli_main([scenario_1_path, "--output", out_path])
            self.assertEqual(ret_code, 0)

            # Check that file was written and is valid JSON
            with open(out_path, "r", encoding="utf-8") as f:
                content = json.load(f)
            self.assertEqual(content["scenario_id"], "scenario_001")
            self.assertIn("entities", content)
            self.assertIn("permissions", content)
            self.assertIn("trust_relationships", content)
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_subprocess_execution(self):
        scenario_1_path = str(self.scenarios_dir / "scenario_001.json")
        proc = subprocess.run(
            [sys.executable, "-m", "parser.main", scenario_1_path],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["scenario_id"], "scenario_001")


if __name__ == "__main__":
    unittest.main()
