"""Attack Path Detection Package (Phase 3).

Identifies valid multi-hop privilege escalation and lateral movement paths
through directed attack graphs.
"""

from path.models import AttackPath
from path.traversal_policy import TraversalPolicy
from path.path_finder import PathFinder, find_attack_paths
from path.path_filter import PathFilter
from path.path_serializer import (
    serialize_paths_to_dict,
    serialize_paths_to_json,
    save_paths_file,
    load_paths_file,
    deserialize_paths_from_dict,
)

__all__ = [
    "AttackPath",
    "TraversalPolicy",
    "PathFinder",
    "find_attack_paths",
    "PathFilter",
    "serialize_paths_to_dict",
    "serialize_paths_to_json",
    "save_paths_file",
    "load_paths_file",
    "deserialize_paths_from_dict",
]
