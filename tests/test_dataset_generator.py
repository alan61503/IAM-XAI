"""Integration tests for the Phase 5 dataset generator end-to-end pipeline."""

import random
import unittest

from dataset.generator import _cap_rows, generate_rows
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

    def test_parallel_generation_matches_serial(self):
        self.assertEqual(generate_rows(count=12, seed=3), generate_rows(count=12, seed=3, workers=2))

    def test_paths_per_scenario_are_capped(self):
        rows = generate_rows(count=60, seed=42, max_paths_per_scenario=10)
        per_scenario = {}
        for row in rows:
            per_scenario[row["scenario_id"]] = per_scenario.get(row["scenario_id"], 0) + 1
        self.assertLessEqual(max(per_scenario.values()), 10)

    def test_cap_keeps_every_label_that_is_present(self):
        rows = [{"risk_label": "LOW"}] * 50 + [{"risk_label": "CRITICAL"}] * 2
        kept = _cap_rows(rows, 12, random.Random(0))
        self.assertEqual(len(kept), 12)
        self.assertEqual(sum(r["risk_label"] == "CRITICAL" for r in kept), 2)

    def test_label_noise_changes_some_labels_only_to_adjacent_classes(self):
        clean = generate_rows(count=100, seed=5)
        noisy = generate_rows(count=100, seed=5, label_noise=0.2)
        changed = [(a["risk_label"], b["risk_label"]) for a, b in zip(clean, noisy) if a["risk_label"] != b["risk_label"]]
        self.assertTrue(changed)
        for before, after in changed:
            self.assertEqual(abs(RISK_LABELS.index(before) - RISK_LABELS.index(after)), 1)

    def test_path_ids_are_unique_within_each_scenario(self):
        rows = generate_rows(count=200, seed=42)
        seen = set()
        for row in rows:
            key = (row["scenario_id"], row["path_id"])
            self.assertNotIn(key, seen)
            seen.add(key)


if __name__ == "__main__":
    unittest.main()
