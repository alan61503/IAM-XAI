"""Serialization and deserialization for DirectedAttackGraph."""

import json
from pathlib import Path
from typing import Any, Dict, Union
from graph.models import DirectedAttackGraph, Edge, Node


def serialize_graph_to_dict(graph: DirectedAttackGraph) -> Dict[str, Any]:
    """Serialize graph into a deterministic dictionary."""
    return graph.to_dict()


def serialize_graph_to_json(graph: DirectedAttackGraph, indent: int = 2) -> str:
    """Serialize graph into a formatted deterministic JSON string."""
    data = serialize_graph_to_dict(graph)
    return json.dumps(data, indent=indent)


def deserialize_graph_from_dict(data: Dict[str, Any]) -> DirectedAttackGraph:
    """Reconstruct a DirectedAttackGraph from serialized dictionary."""
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict for graph data, got {type(data).__name__}")

    scenario_id = data.get("scenario_id", "")
    graph = DirectedAttackGraph(scenario_id=scenario_id)

    # Recreate nodes
    for node_data in data.get("nodes", []):
        node = Node(
            id=node_data["id"],
            type=node_data["type"],
            name=node_data["name"],
            arn=node_data.get("arn"),
            resource_type=node_data.get("resource_type"),
            metadata=node_data.get("metadata", {}),
        )
        graph.add_node(node)

    # Recreate edges
    for edge_data in data.get("edges", []):
        edge = Edge(
            source=edge_data["source"],
            target=edge_data["target"],
            edge_type=edge_data["edge_type"],
            effect=edge_data.get("effect", "Allow"),
            actions=edge_data.get("actions", []),
            resources=edge_data.get("resources", []),
            conditions=edge_data.get("conditions", {}),
            metadata=edge_data.get("metadata", {}),
        )
        graph.add_edge(edge)

    return graph


def save_graph_file(
    graph: DirectedAttackGraph, filepath: Union[str, Path], indent: int = 2
) -> None:
    """Save graph to JSON file path."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_content = serialize_graph_to_json(graph, indent=indent)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_content)
        f.write("\n")


def load_graph_file(filepath: Union[str, Path]) -> DirectedAttackGraph:
    """Load graph from JSON file path."""
    path = Path(filepath)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return deserialize_graph_from_dict(data)
