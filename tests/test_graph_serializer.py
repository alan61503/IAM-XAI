"""Unit tests for graph serialization, determinism, and roundtrip deserialization."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from graph.graph_builder import build_attack_graph
from graph.graph_serializer import (
    deserialize_graph_from_dict,
    load_graph_file,
    save_graph_file,
    serialize_graph_to_dict,
    serialize_graph_to_json,
)
from graph.main import main as cli_main
from parser.normalizer import normalize_scenario_file


class TestGraphSerializer(unittest.TestCase):
    """Test deterministic graph serialization and deserialization."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "data" / "scenarios"
        self.scenario_1_norm = normalize_scenario_file(self.scenarios_dir / "scenario_001.json")
        self.graph = build_attack_graph(self.scenario_1_norm)

    def test_serialization_structure(self):
        data = serialize_graph_to_dict(self.graph)
        self.assertEqual(data["scenario_id"], "scenario_001")
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertEqual(len(data["nodes"]), 3)
        self.assertEqual(len(data["edges"]), 2)

    def test_deterministic_ordering(self):
        # Multiple serializations of same graph produce bit-identical JSON
        json1 = serialize_graph_to_json(self.graph)
        json2 = serialize_graph_to_json(self.graph)
        self.assertEqual(json1, json2)

        # Check nodes are strictly sorted by ID
        data = serialize_graph_to_dict(self.graph)
        node_ids = [n["id"] for n in data["nodes"]]
        self.assertEqual(node_ids, sorted(node_ids))

    def test_roundtrip_deserialization(self):
        json_str = serialize_graph_to_json(self.graph)
        dict_data = json.loads(json_str)
        reconstructed = deserialize_graph_from_dict(dict_data)

        self.assertEqual(reconstructed.scenario_id, self.graph.scenario_id)
        self.assertEqual(len(reconstructed.nodes), len(self.graph.nodes))
        self.assertEqual(len(reconstructed.edges), len(self.graph.edges))

        for node_id, node in self.graph.nodes.items():
            rec_node = reconstructed.get_node(node_id)
            self.assertIsNotNone(rec_node)
            self.assertEqual(rec_node.name, node.name)
            self.assertEqual(rec_node.type, node.type)

    def test_save_and_load_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            save_graph_file(self.graph, tmp_path)
            loaded = load_graph_file(tmp_path)
            self.assertEqual(loaded.scenario_id, self.graph.scenario_id)
            self.assertEqual(len(loaded.nodes), len(self.graph.nodes))
            self.assertEqual(len(loaded.edges), len(self.graph.edges))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_cli_execution_with_output_flag(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            out_path = tmp.name

        try:
            scenario_path = str(self.scenarios_dir / "scenario_001.json")
            ret_code = cli_main([scenario_path, "--output", out_path])
            self.assertEqual(ret_code, 0)

            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["scenario_id"], "scenario_001")
            self.assertIn("nodes", data)
            self.assertIn("edges", data)
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_subprocess_execution(self):
        scenario_path = str(self.scenarios_dir / "scenario_001.json")
        proc = subprocess.run(
            [sys.executable, "-m", "graph.main", scenario_path],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["scenario_id"], "scenario_001")


if __name__ == "__main__":
    unittest.main()
