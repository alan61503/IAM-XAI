"""Attack Graph Construction Package (Phase 2).

Converts Phase 1 normalized IAM configuration data into directed attack graphs
representing privilege relationships between IAM identities and cloud resources.
"""

from graph.models import (
    Node,
    Edge,
    DirectedAttackGraph,
)
from graph.action_mapper import (
    ActionMapper,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_PASS_ROLE,
    EDGE_TYPE_MODIFY,
    ALL_EDGE_TYPES,
)
from graph.resource_matcher import ResourceMatcher
from graph.graph_builder import (
    GraphBuilder,
    build_attack_graph,
)
from graph.graph_serializer import (
    serialize_graph_to_dict,
    serialize_graph_to_json,
    deserialize_graph_from_dict,
    save_graph_file,
    load_graph_file,
)

__all__ = [
    "Node",
    "Edge",
    "DirectedAttackGraph",
    "ActionMapper",
    "ResourceMatcher",
    "GraphBuilder",
    "build_attack_graph",
    "serialize_graph_to_dict",
    "serialize_graph_to_json",
    "deserialize_graph_from_dict",
    "save_graph_file",
    "load_graph_file",
    "EDGE_TYPE_ASSUME",
    "EDGE_TYPE_ACCESS",
    "EDGE_TYPE_PASS_ROLE",
    "EDGE_TYPE_MODIFY",
    "ALL_EDGE_TYPES",
]
