"""Unit tests for path serialization, determinism, and CLI execution."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario_file
from path.main import main as cli_main
from path.models import AttackPath
from path.path_finder import PathFinder
from path.path_serializer import (
    deserialize_paths_from_dict,
    load_paths_file,
    save_paths_file,
    serialize_paths_to_dict,
    serialize_paths_to_json,
)


class TestPathSerializer(unittest.TestCase):
    """Test deterministic path serialization and CLI execution."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "data" / "scenarios"
        normalized = normalize_scenario_file(self.scenarios_dir / "scenario_009.json")
        self.graph = build_attack_graph(normalized)
        finder = PathFinder()
        self.paths = finder.find_paths(
            self.graph,
            source="user:InitialUser",
            target="resource:ProductionDataBucket",
        )

    def test_serialization_structure(self):
        data = serialize_paths_to_dict(
            self.paths,
            scenario_id=self.graph.scenario_id,
            source_filter="user:InitialUser",
            target_filter="resource:ProductionDataBucket",
            max_hops=5,
        )
        self.assertEqual(data["scenario_id"], "scenario_009")
        self.assertEqual(data["source_filter"], "user:InitialUser")
        self.assertEqual(data["target_filter"], "resource:ProductionDataBucket")
        self.assertEqual(data["max_hops"], 5)
        self.assertEqual(data["total_paths"], len(self.paths))
        self.assertIn("paths", data)

    def test_deterministic_serialization(self):
        json1 = serialize_paths_to_json(self.paths, scenario_id="test")
        json2 = serialize_paths_to_json(self.paths, scenario_id="test")
        self.assertEqual(json1, json2)

    def test_roundtrip_deserialization(self):
        json_str = serialize_paths_to_json(self.paths, scenario_id="scenario_009")
        dict_data = json.loads(json_str)
        reconstructed = deserialize_paths_from_dict(dict_data)

        self.assertEqual(len(reconstructed), len(self.paths))
        for orig, rec in zip(self.paths, reconstructed):
            self.assertEqual(orig.path_id, rec.path_id)
            self.assertEqual(orig.source, rec.source)
            self.assertEqual(orig.target, rec.target)
            self.assertEqual(orig.hop_count, rec.hop_count)
            self.assertEqual(orig.nodes, rec.nodes)

    def test_save_and_load_paths_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            save_paths_file(self.paths, tmp_path, scenario_id="scenario_009")
            loaded = load_paths_file(tmp_path)
            self.assertEqual(len(loaded), len(self.paths))
            self.assertEqual(loaded[0].source, "user:InitialUser")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_cli_execution_with_output_flag(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            out_path = tmp.name

        try:
            graph_path = str(Path(__file__).resolve().parent.parent / "output" / "scenario_009_graph.json")
            ret_code = cli_main(
                [
                    graph_path,
                    "--source",
                    "user:InitialUser",
                    "--target",
                    "resource:ProductionDataBucket",
                    "--output",
                    out_path,
                ]
            )
            self.assertEqual(ret_code, 0)

            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["scenario_id"], "scenario_009")
            self.assertTrue(len(data["paths"]) >= 1)
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_subprocess_execution(self):
        graph_path = str(Path(__file__).resolve().parent.parent / "output" / "scenario_001_graph.json")
        proc = subprocess.run(
            [sys.executable, "-m", "path.main", graph_path],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["scenario_id"], "scenario_001")
        self.assertEqual(len(parsed["paths"]), 1)


if __name__ == "__main__":
    unittest.main()
