"""Integration tests for the Phase 5 dataset generator end-to-end pipeline."""

import unittest

from dataset.generator import generate_rows
from dataset.schema import ATTACK_TYPES, DATASET_COLUMNS, RISK_LABELS


class TestDatasetGenerator(unittest.TestCase):
    def test_generate_rows_is_deterministic_for_a_fixed_seed(self):
        rows_a = generate_rows(count=150, seed=42)
        rows_b = generate_rows(count=150, seed=42)
        self.assertEqual(rows_a, rows_b)

    def test_different_seeds_can_differ(self):
        rows_a = generate_rows(count=150, seed=42)
        rows_b = generate_rows(count=150, seed=1)
        self.assertNotEqual(rows_a, rows_b)

    def test_row_schema_matches_dataset_columns(self):
        rows = generate_rows(count=50, seed=42)
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(path_id=row.get("path_id")):
                self.assertEqual(set(row.keys()), set(DATASET_COLUMNS))
                self.assertIn(row["risk_label"], RISK_LABELS)
                self.assertIn(row["attack_type"], ATTACK_TYPES)

    def test_all_four_risk_labels_are_reachable_at_scale(self):
        rows = generate_rows(count=800, seed=42)
        labels = {row["risk_label"] for row in rows}
        self.assertEqual(labels, set(RISK_LABELS))

    def test_path_ids_are_unique_within_each_scenario(self):
        rows = generate_rows(count=200, seed=42)
        seen = set()
        for row in rows:
            key = (row["scenario_id"], row["path_id"])
            self.assertNotIn(key, seen)
            seen.add(key)


if __name__ == "__main__":
    unittest.main()
