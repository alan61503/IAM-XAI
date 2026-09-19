"""Tests that every scenario template in dataset/scenario_library.py builds a
valid graph and produces at least one attack path with the expected ground
truth label, using the real Phase 1-4 pipeline (no mocking)."""

import random
import unittest

from dataset.generator import _build_row, _discover_paths
from dataset.scenario_library import REGISTRY
from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario

EXPECTED_LABEL = {
    "read_only": "LOW",
    "wildcard_s3": "MEDIUM",
    "pass_role_escalation": "HIGH",
    "assume_role_chain": "HIGH",
    "long_chain": "HIGH",
    "external_trust_critical": "CRITICAL",
    "policy_modification": "CRITICAL",
    "cross_account_wildcard": "CRITICAL",
    "admin_wildcard": "CRITICAL",
}


class TestScenarioLibrary(unittest.TestCase):
    def _rows_for(self, scenario_type: str, seed: int = 7):
        builder, _weight = REGISTRY[scenario_type]
        rng = random.Random(seed)
        raw_scenario, meta = builder(rng, f"test_{scenario_type}")
        graph = build_attack_graph(normalize_scenario(raw_scenario))
        paths = _discover_paths(graph, meta)
        return [_build_row(p.to_dict(), meta) for p in paths]

    def test_registry_covers_every_expected_scenario(self):
        self.assertEqual(set(REGISTRY.keys()), set(EXPECTED_LABEL.keys()))

    def test_every_scenario_produces_at_least_one_path(self):
        for scenario_type in REGISTRY:
            with self.subTest(scenario_type=scenario_type):
                rows = self._rows_for(scenario_type)
                self.assertGreaterEqual(len(rows), 1)

    def test_every_scenario_matches_its_expected_label(self):
        for scenario_type, expected_label in EXPECTED_LABEL.items():
            with self.subTest(scenario_type=scenario_type):
                rows = self._rows_for(scenario_type)
                labels = {row["risk_label"] for row in rows}
                self.assertIn(expected_label, labels)

    def test_pass_role_scenario_reaches_role_target_via_pass_role_edge(self):
        rows = self._rows_for("pass_role_escalation")
        self.assertTrue(any(row["pass_role"] == 1 for row in rows))

    def test_external_trust_scenario_flags_external_principal(self):
        rows = self._rows_for("external_trust_critical")
        self.assertTrue(any(row["external_trust"] == 1 for row in rows))

    def test_cross_account_scenario_flags_cross_account(self):
        rows = self._rows_for("cross_account_wildcard")
        self.assertTrue(any(row["cross_account"] == 1 for row in rows))

    def test_builders_are_deterministic_for_a_given_seed(self):
        for scenario_type, (builder, _weight) in REGISTRY.items():
            with self.subTest(scenario_type=scenario_type):
                raw_a, _ = builder(random.Random(99), "s")
                raw_b, _ = builder(random.Random(99), "s")
                self.assertEqual(raw_a, raw_b)


if __name__ == "__main__":
    unittest.main()
