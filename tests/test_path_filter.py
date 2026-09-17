"""Unit tests for PathFilter component."""

import unittest
from path.models import AttackPath
from path.path_filter import PathFilter


class TestPathFilter(unittest.TestCase):
    """Test filtering discovered attack paths."""

    def setUp(self):
        self.path_1 = AttackPath(
            path_id="path_001",
            scenario_id="test",
            source="user:UserA",
            target="resource:BucketA",
            nodes=["user:UserA", "role:RoleA", "resource:BucketA"],
            edges=[],
            hop_count=2,
            conditional=False,
            edge_types=["CAN_ASSUME", "CAN_ACCESS"],
        )
        self.path_2 = AttackPath(
            path_id="path_002",
            scenario_id="test",
            source="user:UserA",
            target="resource:BucketB",
            nodes=["user:UserA", "role:RoleA", "role:RoleB", "resource:BucketB"],
            edges=[],
            hop_count=3,
            conditional=True,
            edge_types=["CAN_ASSUME", "CAN_ASSUME", "CAN_MODIFY"],
        )
        self.path_3 = AttackPath(
            path_id="path_003",
            scenario_id="test",
            source="user:UserB",
            target="resource:BucketA",
            nodes=["user:UserB", "role:RoleA", "resource:BucketA"],
            edges=[],
            hop_count=2,
            conditional=False,
            edge_types=["CAN_ASSUME", "CAN_ACCESS"],
        )
        self.all_paths = [self.path_1, self.path_2, self.path_3]

    def test_filter_by_min_hops(self):
        f = PathFilter(min_hops=3)
        filtered = f.filter_paths(self.all_paths)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].path_id, "path_002")

    def test_filter_by_max_hops(self):
        f = PathFilter(max_hops=2)
        filtered = f.filter_paths(self.all_paths)
        self.assertEqual(len(filtered), 2)
        path_ids = {p.path_id for p in filtered}
        self.assertEqual(path_ids, {"path_001", "path_003"})

    def test_filter_by_source(self):
        f = PathFilter(source="user:UserB")
        filtered = f.filter_paths(self.all_paths)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].path_id, "path_003")

    def test_filter_by_target(self):
        f = PathFilter(target="resource:BucketB")
        filtered = f.filter_paths(self.all_paths)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].path_id, "path_002")

    def test_filter_by_conditional(self):
        f_cond = PathFilter(conditional=True)
        self.assertEqual(len(f_cond.filter_paths(self.all_paths)), 1)

        f_uncond = PathFilter(conditional=False)
        self.assertEqual(len(f_uncond.filter_paths(self.all_paths)), 2)

    def test_filter_by_edge_type(self):
        f_modify = PathFilter(edge_types=["CAN_MODIFY"])
        filtered = f_modify.filter_paths(self.all_paths)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].path_id, "path_002")


if __name__ == "__main__":
    unittest.main()
