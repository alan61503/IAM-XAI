"""Tests that synthetic environments are well-formed and every injected attack
pattern produces attack paths exhibiting it, using the real Phase 1-4 pipeline
(no mocking)."""

import random
import unittest

from dataset.generator import build_labeled_row, discover_paths
from dataset.row_builder import context_from_scenario
from dataset.scenario_library import PATTERNS, RESOURCE_RANGE, ROLE_RANGE, USER_RANGE, build_environment
from graph.graph_builder import build_attack_graph
from parser.normalizer import normalize_scenario

# pattern -> predicate over a dataset row that shows the pattern was exercised
PATTERN_SIGNATURE = {
    "wildcard_action": lambda row: row["wildcard_action"] == 1,
    "wildcard_resource": lambda row: row["wildcard_resource"] == 1,
    "pass_role": lambda row: row["pass_role"] == 1,
    "assume_chain": lambda row: row["role_count"] >= 2,
    "external_trust": lambda row: row["external_trust"] == 1,
    "cross_account": lambda row: row["cross_account"] == 1,
    "wildcard_trust": lambda row: row["wildcard_principal"] == 1,
    "policy_modification": lambda row: row["policy_modification"] == 1,
    "admin_wildcard": lambda row: row["admin_permission"] == 1,
}


def _rows_for(patterns, seed=7):
    raw, meta = build_environment(random.Random(seed), "test_env", patterns=patterns)
    context = context_from_scenario(raw)
    graph = build_attack_graph(normalize_scenario(raw))
    return raw, meta, [build_labeled_row(p.to_dict(), context, meta) for p in discover_paths(graph, context)]


class TestScenarioLibrary(unittest.TestCase):
    def test_every_pattern_has_a_signature(self):
        self.assertEqual(set(PATTERNS), set(PATTERN_SIGNATURE))

    def test_baseline_entity_counts_follow_spec_ranges(self):
        for seed in range(10):
            raw, _meta, _rows = _rows_for([], seed=seed)
            with self.subTest(seed=seed):
                self.assertTrue(USER_RANGE[0] <= len(raw["users"]) <= USER_RANGE[1])
                self.assertTrue(ROLE_RANGE[0] <= len(raw["roles"]) <= ROLE_RANGE[1])
                self.assertTrue(RESOURCE_RANGE[0] <= len(raw["resources"]) <= RESOURCE_RANGE[1])

    def test_entity_names_are_unique_within_an_environment(self):
        raw, _meta, _rows = _rows_for(list(PATTERNS))
        names = [e["name"] for key in ("users", "roles", "resources") for e in raw[key]]
        self.assertEqual(len(names), len(set(names)))

    def test_every_pattern_produces_a_path_that_exercises_it(self):
        for pattern, signature in PATTERN_SIGNATURE.items():
            with self.subTest(pattern=pattern):
                hits = sum(any(signature(row) for row in _rows_for([pattern], seed=s)[2]) for s in range(5))
                self.assertGreaterEqual(hits, 4, f"{pattern} rarely produced a matching path")

    def test_meta_records_injected_patterns_and_ground_truth(self):
        raw, meta, _rows = _rows_for(["pass_role", "external_trust"])
        self.assertEqual(meta["patterns"], ["pass_role", "external_trust"])
        self.assertEqual(set(meta["resource_tiers"]), {r["name"] for r in raw["resources"]})
        self.assertTrue(all(0 <= tier <= 3 for tier in meta["resource_tiers"].values()))

    def test_sensitive_tags_are_imperfect_proxies_for_true_tier(self):
        tagged_high, untagged_high = 0, 0
        for seed in range(30):
            raw, meta, _ = _rows_for([], seed=seed)
            for res in raw["resources"]:
                if meta["resource_tiers"][res["name"]] >= 2:
                    tagged_high += bool(res.get("sensitive"))
                    untagged_high += not res.get("sensitive")
        self.assertGreater(tagged_high, untagged_high)
        self.assertGreater(untagged_high, 0)

    def test_builder_is_deterministic_for_a_given_seed(self):
        a = build_environment(random.Random(99), "s")
        b = build_environment(random.Random(99), "s")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
