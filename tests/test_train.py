"""Tests for Phase 6 model building and evaluation (models/train.py, models/evaluate.py).

Exercises the training/evaluation logic in-memory against a small fixture
dataset; deliberately does not invoke ``models.train.main()``, since that CLI
writes its ``.pkl`` artifacts straight into ``models/``, which would clobber
the real trained models.
"""

import unittest

import pandas as pd

from dataset.generator import generate_rows
from dataset.schema import DATASET_COLUMNS, RISK_LABELS
from models.evaluate import evaluate_models
from models.estimators import LabelEncodedClassifier
from models.preprocess import split_dataset
from models.train import _HAS_XGBOOST, build_models


class TestTrain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = generate_rows(count=200, seed=42)
        cls.df = pd.DataFrame(rows, columns=DATASET_COLUMNS)
        cls.X_train, cls.X_val, cls.X_test, cls.y_train, cls.y_val, cls.y_test = split_dataset(cls.df)

    def test_build_models_includes_logistic_regression_and_random_forest(self):
        models = build_models()
        self.assertIn("logistic_regression", models)
        self.assertIn("random_forest", models)
        self.assertEqual("xgboost" in models, _HAS_XGBOOST)

    def test_trained_models_predict_known_risk_labels(self):
        models = build_models()
        for model in models.values():
            model.fit(self.X_train, self.y_train)
            predictions = model.predict(self.X_test)
            self.assertTrue(set(predictions).issubset(set(RISK_LABELS)))

    def test_evaluate_models_reports_expected_metric_keys(self):
        models = build_models()
        for model in models.values():
            model.fit(self.X_train, self.y_train)

        metrics = evaluate_models(models, self.X_test, self.y_test, feature_names=list(self.X_train.columns))

        for name in models:
            with self.subTest(model=name):
                entry = metrics[name]
                for key in ("accuracy", "precision_weighted", "recall_weighted", "f1_weighted", "confusion_matrix"):
                    self.assertIn(key, entry)

        self.assertIn("feature_importance", metrics["random_forest"])
        self.assertTrue(metrics["random_forest"]["feature_importance"])

    def test_models_beat_the_majority_class_on_unseen_scenarios(self):
        model = build_models()["random_forest"].fit(self.X_train, self.y_train)
        majority = self.y_test.value_counts(normalize=True).iloc[0]
        self.assertGreater((model.predict(self.X_test) == self.y_test).mean(), majority + 0.2)

    def test_label_encoded_classifier_round_trips_string_labels(self):
        from sklearn.tree import DecisionTreeClassifier

        model = LabelEncodedClassifier(DecisionTreeClassifier(random_state=0)).fit(self.X_train, self.y_train)
        self.assertTrue(set(model.predict(self.X_test)).issubset(set(RISK_LABELS)))
        self.assertEqual(model.predict_proba(self.X_test).shape[1], len(model.classes_))


if __name__ == "__main__":
    unittest.main()
