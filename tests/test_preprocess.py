"""Tests for Phase 6 preprocessing (models/preprocess.py)."""

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from dataset.generator import generate_rows
from dataset.schema import DATASET_COLUMNS
from models.preprocess import (
    BINARY_FEATURES,
    LABEL_COLUMN,
    NUMERIC_FEATURES,
    align_features,
    build_feature_matrix,
    load_dataset,
    split_dataset,
)


def _write_fixture_csv() -> str:
    rows = generate_rows(count=200, seed=42)
    df = pd.DataFrame(rows, columns=DATASET_COLUMNS)
    tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv")
    df.to_csv(tmp.name, index=False)
    return tmp.name


class TestPreprocess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csv_path = _write_fixture_csv()
        cls.df = load_dataset(cls.csv_path)

    @classmethod
    def tearDownClass(cls):
        Path(cls.csv_path).unlink(missing_ok=True)

    def test_feature_matrix_has_no_raw_categorical_columns(self):
        X = build_feature_matrix(self.df)
        for col in NUMERIC_FEATURES + BINARY_FEATURES:
            self.assertIn(col, X.columns)
        self.assertNotIn("target_service", X.columns)
        self.assertTrue(any(c.startswith("target_service_") for c in X.columns))

    def test_feature_matrix_excludes_ground_truth_columns(self):
        X = build_feature_matrix(self.df)
        for leaked in ("risk_score", "attack_type", "risk_cause", "scenario_patterns", "target_classification"):
            self.assertFalse(any(c == leaked or c.startswith(leaked + "_") for c in X.columns), leaked)

    def test_split_is_roughly_70_15_15_by_scenario(self):
        X_train, X_val, X_test, y_train, y_val, y_test = split_dataset(self.df)
        scenarios = self.df["scenario_id"]
        total = scenarios.nunique()

        split_scenarios = [set(scenarios.loc[X.index]) for X in (X_train, X_val, X_test)]
        self.assertAlmostEqual(len(split_scenarios[0]) / total, 0.70, delta=0.02)
        self.assertAlmostEqual(len(split_scenarios[1]) / total, 0.15, delta=0.02)
        self.assertAlmostEqual(len(split_scenarios[2]) / total, 0.15, delta=0.02)
        self.assertEqual(len(X_train) + len(X_val) + len(X_test), len(self.df))

        for split_labels in (y_train, y_val, y_test):
            self.assertEqual(set(split_labels), set(self.df[LABEL_COLUMN]))

    def test_no_scenario_is_shared_between_splits(self):
        X_train, X_val, X_test, *_ = split_dataset(self.df)
        train, val, test = (set(self.df.loc[X.index, "scenario_id"]) for X in (X_train, X_val, X_test))
        self.assertFalse(train & val or train & test or val & test)

    def test_align_features_fills_missing_dummy_columns_with_zero(self):
        X = build_feature_matrix(self.df)
        one_row = X.iloc[[0]]
        wider_columns = list(X.columns) + ["target_service_NeverSeen"]

        aligned = align_features(one_row, wider_columns)

        self.assertEqual(list(aligned.columns), wider_columns)
        self.assertEqual(aligned["target_service_NeverSeen"].iloc[0], 0)


if __name__ == "__main__":
    unittest.main()
