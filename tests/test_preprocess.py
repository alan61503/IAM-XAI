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
    rows = generate_rows(count=150, seed=42)
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

    def test_load_dataset_derives_target_type(self):
        self.assertIn("target_type", self.df.columns)
        self.assertTrue(set(self.df["target_type"]).issubset({"user", "role", "resource"}))

    def test_feature_matrix_has_no_raw_categorical_columns(self):
        X = build_feature_matrix(self.df)
        for col in NUMERIC_FEATURES + BINARY_FEATURES:
            self.assertIn(col, X.columns)
        self.assertNotIn("attack_type", X.columns)
        self.assertTrue(any(c.startswith("attack_type_") for c in X.columns))

    def test_split_is_70_15_15_and_stratified(self):
        X_train, X_val, X_test, y_train, y_val, y_test = split_dataset(self.df)
        total = len(self.df)

        self.assertAlmostEqual(len(X_train) / total, 0.70, delta=0.02)
        self.assertAlmostEqual(len(X_val) / total, 0.15, delta=0.02)
        self.assertAlmostEqual(len(X_test) / total, 0.15, delta=0.02)

        for split_labels in (y_train, y_val, y_test):
            self.assertEqual(set(split_labels), set(self.df[LABEL_COLUMN]))

    def test_align_features_fills_missing_dummy_columns_with_zero(self):
        X = build_feature_matrix(self.df)
        one_row = X.iloc[[0]]
        wider_columns = list(X.columns) + ["attack_type_NeverSeen"]

        aligned = align_features(one_row, wider_columns)

        self.assertEqual(list(aligned.columns), wider_columns)
        self.assertEqual(aligned["attack_type_NeverSeen"].iloc[0], 0)


if __name__ == "__main__":
    unittest.main()
