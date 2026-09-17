"""Tests for the Phase 4 feature serializer.

Ensures deterministic JSON and CSV output, proper column ordering and
behaviour for empty input.
"""

import unittest
import json
import csv
from pathlib import Path

from features.feature_serializer import to_json, to_csv
from features.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

class TestFeatureSerializer(unittest.TestCase):
    def setUp(self):
        # Create a minimal record list used in several tests
        self.record = {
            "scenario_id": "sc001",
            "path_id": "p1",
            "source": "user:U1",
            "target": "resource:R1",
            "features": {name: 0 for name in FEATURE_NAMES},
        }
        self.records = [self.record]
        self.tmp_dir = Path.cwd() / "tmp_test_serializer"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.json_path = self.tmp_dir / "features.json"
        self.csv_path = self.tmp_dir / "features.csv"

    def tearDown(self):
        for p in self.tmp_dir.iterdir():
            p.unlink()
        self.tmp_dir.rmdir()

    def test_json_structure(self):
        to_json(self.records, self.json_path)
        content = json.loads(self.json_path.read_text())
        self.assertEqual(content["scenario_id"], "sc001")
        self.assertEqual(content["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertIsInstance(content["records"], list)
        self.assertEqual(len(content["records"]), 1)
        rec = content["records"][0]
        self.assertEqual(rec["path_id"], "p1")
        self.assertIn("features", rec)
        # Ensure feature ordering matches FEATURE_NAMES
        self.assertEqual(list(rec["features"].keys()), FEATURE_NAMES)

    def test_csv_column_ordering(self):
        to_csv(self.records, self.csv_path)
        with self.csv_path.open(newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
        expected_header = ["scenario_id", "path_id", "source", "target"] + FEATURE_NAMES
        self.assertEqual(header, expected_header)
        # Verify that a data row exists and has correct number of columns
        with self.csv_path.open(newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 2)  # header + one record
        self.assertEqual(len(rows[1]), len(expected_header))

    def test_empty_records_error(self):
        with self.assertRaises(ValueError):
            to_json([], self.json_path)
        with self.assertRaises(ValueError):
            to_csv([], self.csv_path)

    def test_deterministic_output_consistency(self):
        # Running serializer twice must produce identical files
        to_json(self.records, self.json_path)
        first = self.json_path.read_text()
        to_json(self.records, self.json_path)
        second = self.json_path.read_text()
        self.assertEqual(first, second)
        to_csv(self.records, self.csv_path)
        first_csv = self.csv_path.read_text()
        to_csv(self.records, self.csv_path)
        second_csv = self.csv_path.read_text()
        self.assertEqual(first_csv, second_csv)

if __name__ == "__main__":
    unittest.main()
