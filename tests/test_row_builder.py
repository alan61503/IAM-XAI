"""Tests for the shared feature-row builder (dataset/row_builder.py)."""

import random
import unittest

from dataset.generator import build_labeled_row, discover_paths
from dataset.row_builder import build_feature_row, context_from_scenario, target_service
from dataset.scenario_library import build_environment
from dataset.schema import FEATURE_COLUMNS, IDENTIFIER_COLUMNS
from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario


class TestRowBuilder(unittest.TestCase):
    def setUp(self):
        self.raw = {
            "scenario_id": "s",
            "users": [{"name": "U"}],
            "roles": [
                {
                    "name": "R",
                    "trust_policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "U"}, "Action": "sts:AssumeRole"}]},
                    "permissions": [
                        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:aws:secretsmanager:us-east-1:1:secret:x"},
                        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/Svc"},
                    ],
                },
                {"name": "Svc"},
            ],
            "resources": [
                {
                    "name": "Secret",
                    "type": "secretsmanager",
                    "arn": "arn:aws:secretsmanager:us-east-1:1:secret:x",
                    "tags": {"DataClassification": "Restricted"},
                },
                {"name": "Bucket", "type": "s3", "arn": "arn:aws:s3:::b", "sensitive": True},
            ],
        }

    def test_context_reads_tags_types_and_pass_role_targets(self):
        ctx = context_from_scenario(self.raw)
        self.assertEqual(ctx["sensitive_resources"], ["Bucket", "Secret"])
        self.assertEqual(ctx["classification_tags"], {"Secret": 3})
        self.assertEqual(ctx["resource_types"]["Secret"], "secretsmanager")
        self.assertEqual(ctx["pass_role_targets"], ["Svc"])

    def test_target_service(self):
        ctx = context_from_scenario(self.raw)
        self.assertEqual(target_service("resource:Secret", ctx), "secretsmanager")
        self.assertEqual(target_service("role:Svc", ctx), "iam_role")
        self.assertEqual(target_service("resource:arn:aws:kms:us-east-1:1:key/k", ctx), "kms")

    def test_rows_contain_exactly_identifiers_and_features(self):
        ctx = context_from_scenario(self.raw)
        graph = build_attack_graph(normalize_scenario(self.raw))
        paths = discover_paths(graph, ctx)
        self.assertTrue(any(p.target == "role:Svc" for p in paths))
        for path in paths:
            row = build_feature_row(path.to_dict(), ctx)
            self.assertEqual(set(row), set(IDENTIFIER_COLUMNS + FEATURE_COLUMNS))

        secret_row = next(build_feature_row(p.to_dict(), ctx) for p in paths if p.target == "resource:Secret")
        self.assertEqual(secret_row["classification_tag"], 3)
        self.assertEqual(secret_row["sensitive_target"], 1)
        self.assertEqual(secret_row["target_service"], "secretsmanager")

    def test_training_and_serving_features_are_identical(self):
        """The dashboard only sees the raw scenario; features must equal the dataset's."""
        raw, meta = build_environment(random.Random(3), "parity", patterns=["pass_role", "external_trust"])
        ctx = context_from_scenario(raw)
        graph = build_attack_graph(normalize_scenario(raw))
        for path in discover_paths(graph, ctx):
            training_row = build_labeled_row(path.to_dict(), ctx, meta)
            serving_row = build_feature_row(path.to_dict(), context_from_scenario(raw))
            self.assertEqual({k: training_row[k] for k in serving_row}, serving_row)


if __name__ == "__main__":
    unittest.main()
