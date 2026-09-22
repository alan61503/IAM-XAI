"""Tests for the research-evaluation code: statistics, hybrid floor, explanation
faithfulness helpers, greedy choke-point selection, sensitivity variants and the
external benchmark scenarios."""

import unittest

import pandas as pd

from choke_point.choke_finder import greedy_edge_cut, select_choke_point_set
from dataset.generator import discover_paths
from dataset.label_generator import DEFAULT_ORACLE
from dataset.row_builder import context_from_scenario
from experiments.benchmark import modelled_scenarios, negative_controls, rhino_techniques
from experiments.sensitivity import perturbed_oracle, shifted_thresholds
from explainability.faithfulness import cause_drivers, cause_recovery
from graph.graph_builder import build_attack_graph
from models.baselines import apply_escalation_floor
from models.evaluate import grouped_bootstrap, mcnemar
from models.train import severe_miss_rate
from parser.normalizer import normalize_scenario


def _row(**flags):
    base = {"admin_permission": 0, "policy_modification": 0, "pass_role": 0, "target_privileged": 0}
    base.update(flags)
    return base


class TestStatistics(unittest.TestCase):
    def test_severe_miss_rate_counts_only_high_and_critical_truths(self):
        truth = ["HIGH", "CRITICAL", "LOW", "HIGH"]
        pred = ["MEDIUM", "CRITICAL", "HIGH", "HIGH"]
        self.assertAlmostEqual(severe_miss_rate(truth, pred), 1 / 3, places=4)

    def test_grouped_bootstrap_interval_contains_point_estimate(self):
        truth = ["LOW", "HIGH", "MEDIUM", "CRITICAL"] * 50
        good = list(truth)
        bad = ["LOW"] * len(truth)
        groups = [f"s{i // 4}" for i in range(len(truth))]
        result = grouped_bootstrap(truth, {"good": good, "bad": bad}, groups, reference="good", n_boot=200)
        self.assertEqual(result["intervals"]["good"]["accuracy_95ci"], [1.0, 1.0])
        lo, hi = result["vs_good"]["bad"]["f1_macro_difference_95ci"]
        self.assertGreater(lo, 0)
        self.assertEqual(result["vs_good"]["bad"]["p_value_reference_not_better"], 0.0)

    def test_mcnemar_identical_predictions_is_not_significant(self):
        truth = ["LOW", "HIGH"] * 10
        self.assertEqual(mcnemar(truth, truth, truth)["p_value"], 1.0)


class TestEscalationFloor(unittest.TestCase):
    def test_floor_raises_escalation_primitives(self):
        df = pd.DataFrame([
            _row(admin_permission=1),
            _row(policy_modification=1),
            _row(pass_role=1, target_privileged=1),
            _row(pass_role=1),
            _row(),
        ])
        self.assertEqual(
            apply_escalation_floor(["LOW"] * 5, df),
            ["HIGH", "HIGH", "HIGH", "MEDIUM", "LOW"],
        )

    def test_floor_never_lowers_a_label(self):
        df = pd.DataFrame([_row(pass_role=1)])
        self.assertEqual(apply_escalation_floor(["CRITICAL"], df), ["CRITICAL"])


class TestFaithfulnessHelpers(unittest.TestCase):
    def test_cause_drivers_parses_oracle_causes(self):
        self.assertEqual(cause_drivers("restricted_data_write + external_trust + mfa_mitigated"),
                         {"data_classification", "write_access", "external_trust", "mitigation"})
        self.assertEqual(cause_drivers("pass_role_to_privileged_role"), {"pass_role"})
        self.assertEqual(cause_drivers("admin_permission + long_chain"), {"admin_permission", "long_chain"})

    def test_cause_recovery_scores_rankings(self):
        rankings = [["external_trust", "path_length", "has_conditions"], ["path_length", "has_conditions", "user_count"]]
        causes = ["confidential_data + external_trust", "internal_data"]
        result = cause_recovery(rankings, causes)
        self.assertEqual(result["top1_hit_rate"], 0.5)
        self.assertAlmostEqual(result["cause_recall_at_3"], 0.25)


class TestChokePointSelection(unittest.TestCase):
    def test_greedy_prefers_uncovered_risk(self):
        # "b" covers 2.5 of risk vs "a" 2.0. Once "b" is cut, "a" covers nothing new,
        # so the second cut goes to "c" rather than the overlapping "a".
        path_edges = [{"a", "b"}, {"a", "b"}, {"c"}, {"c"}, {"b"}]
        weights = [1.0, 1.0, 0.8, 0.8, 0.5]
        self.assertEqual(greedy_edge_cut(path_edges, weights, 2), ["b", "c"])

    def test_select_choke_point_set_uses_expected_risk(self):
        edge = lambda s, t: {"source": s, "target": t, "edge_type": "CAN_ACCESS", "actions": ["s3:GetObject"]}
        paths = [
            {"path_id": "p1", "edges": [edge("user:U", "resource:A")]},
            {"path_id": "p2", "edges": [edge("user:U", "resource:B")]},
        ]
        preds = [{"path_id": "p1", "expected_risk": 0.1}, {"path_id": "p2", "expected_risk": 0.9}]
        self.assertEqual(len(select_choke_point_set(paths, preds, 1)), 1)
        self.assertIn("resource:B", select_choke_point_set(paths, preds, 1)[0])


class TestSensitivityVariants(unittest.TestCase):
    def test_perturbed_oracle_is_deterministic_and_keeps_tier_order(self):
        a, b = perturbed_oracle(7), perturbed_oracle(7)
        self.assertEqual(a, b)
        self.assertEqual(list(a.tier_impact), sorted(a.tier_impact))
        self.assertNotEqual(a, DEFAULT_ORACLE)

    def test_shifted_thresholds_scale_every_cut_point(self):
        shifted = shifted_thresholds(1.1)
        for (_, new), (_, old) in zip(shifted.thresholds, DEFAULT_ORACLE.thresholds):
            self.assertAlmostEqual(new, old * 1.1, places=4)


class TestBenchmarkScenarios(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(rhino_techniques()), 21)
        self.assertEqual(len(modelled_scenarios()), 5)
        self.assertEqual(len(negative_controls()), 6)

    def test_every_scenario_is_valid_and_yields_attack_paths(self):
        for entry in rhino_techniques() + modelled_scenarios() + negative_controls():
            with self.subTest(scenario=entry["id"]):
                raw = entry["scenario"]
                paths = discover_paths(build_attack_graph(normalize_scenario(raw)), context_from_scenario(raw))
                self.assertTrue(paths)


if __name__ == "__main__":
    unittest.main()
