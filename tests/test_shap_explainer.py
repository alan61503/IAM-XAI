"""Smoke tests for Phase 7 SHAP explainability, against a tiny trained Random Forest
(not the real models/random_forest.pkl, so this never touches shipped artifacts).
"""

import unittest

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from dataset.generator import generate_rows
from dataset.schema import DATASET_COLUMNS
from explainability.shap_explainer import base_value_for_class, build_explainer, shap_values_for_class
from explainability.explain_prediction import explain_rows
from models.preprocess import build_feature_matrix


class TestShapExplainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = generate_rows(count=200, seed=42)
        cls.df = pd.DataFrame(rows, columns=DATASET_COLUMNS)
        cls.X = build_feature_matrix(cls.df)
        cls.y = cls.df["risk_label"]

        cls.model = RandomForestClassifier(random_state=42, n_estimators=20)
        cls.model.fit(cls.X, cls.y)
        cls.explainer = build_explainer(cls.model)

    def test_shap_values_shape_matches_features(self):
        row = self.X.iloc[[0]]
        label = self.model.predict(row)[0]
        contributions = shap_values_for_class(self.explainer, row, self.model, label)
        self.assertEqual(contributions.shape, (1, len(self.X.columns)))

    def test_shap_values_plus_base_value_reconstructs_model_output(self):
        row = self.X.iloc[[0]]
        label = self.model.predict(row)[0]
        class_index = list(self.model.classes_).index(label)

        contributions = shap_values_for_class(self.explainer, row, self.model, label)[0]
        base_value = base_value_for_class(self.explainer, self.model, label)
        predicted_proba = self.model.predict_proba(row)[0][class_index]

        self.assertAlmostEqual(base_value + contributions.sum(), predicted_proba, places=4)

    def test_top_factors_are_sorted_by_absolute_impact(self):
        row = self.X.iloc[[0]]
        label = self.model.predict(row)[0]
        contributions = shap_values_for_class(self.explainer, row, self.model, label)[0]

        ranked = sorted(zip(self.X.columns, contributions), key=lambda kv: abs(kv[1]), reverse=True)[:6]
        impacts = [abs(value) for _, value in ranked]
        self.assertEqual(impacts, sorted(impacts, reverse=True))

    def test_explain_rows_matches_per_row_shap_despite_deduplication(self):
        sample = self.df.iloc[:40]
        explanations = explain_rows(sample, feature_columns=list(self.X.columns), model=self.model)
        self.assertEqual([e["path_id"] for e in explanations], list(sample["path_id"]))

        for idx in (0, 17, 39):
            row = self.X.iloc[[idx]]
            label = self.model.predict(row)[0]
            contributions = shap_values_for_class(self.explainer, row, self.model, label)[0]
            top = max(zip(self.X.columns, contributions), key=lambda kv: abs(kv[1]))
            self.assertEqual(explanations[idx]["prediction"], label)
            self.assertEqual(explanations[idx]["top_factors"][0]["feature"], top[0])
            self.assertAlmostEqual(explanations[idx]["top_factors"][0]["impact"], top[1], places=3)


if __name__ == "__main__":
    unittest.main()
