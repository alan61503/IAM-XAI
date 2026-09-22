"""Core graph data models for IAM directed attack graph."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Node:
    """Represents a node in the attack graph (IAM entity or cloud resource)."""
    id: str
    type: str  # 'user', 'role', 'resource', 'group', 'service', 'principal'
    name: str
    arn: Optional[str] = None
    resource_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert Node to dictionary matching canonical schema."""
        data: Dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "name": self.name,
        }
        if self.arn is not None:
            data["arn"] = self.arn
        if self.resource_type is not None:
            data["resource_type"] = self.resource_type
        if self.metadata:
            data["metadata"] = self.metadata
        return data


@dataclass
class Edge:
    """Represents a directed relationship edge between nodes in the attack graph."""
    source: str  # Node ID of source
    target: str  # Node ID of target
    edge_type: str  # 'CAN_ASSUME', 'CAN_ACCESS', 'CAN_PASS_ROLE', 'CAN_MODIFY'
    effect: str = "Allow"  # 'Allow' or 'Deny'
    actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert Edge to dictionary matching canonical schema."""
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "effect": self.effect,
            "actions": sorted(self.actions),
            "resources": sorted(self.resources),
            "conditions": self.conditions,
            "metadata": self.metadata,
        }

    def identity_key(self) -> tuple:
        """Key used for edge deduplication."""
        import json
        cond_str = json.dumps(self.conditions, sort_keys=True) if self.conditions else ""
        return (
            self.source,
            self.target,
            self.edge_type,
            self.effect,
            tuple(sorted(self.actions)),
            tuple(sorted(self.resources)),
            cond_str,
        )


class DirectedAttackGraph:
    """Directed graph representing privilege relationships between entities and resources."""

    def __init__(self, scenario_id: str = ""):
        self.scenario_id: str = scenario_id
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge] = []
        self._edge_keys: set = set()
        self._out_edges: Dict[str, List[Edge]] = {}

    @property
    def nodes(self) -> Dict[str, Node]:
        return self._nodes

    @property
    def edges(self) -> List[Edge]:
        return self._edges

    def add_node(self, node: Node) -> Node:
        """Add or update a node in the graph."""
        if node.id in self._nodes:
            # Merge / preserve existing properties if new one lacks them
            existing = self._nodes[node.id]
            if not existing.arn and node.arn:
                existing.arn = node.arn
            if not existing.resource_type and node.resource_type:
                existing.resource_type = node.resource_type
            if node.metadata:
                existing.metadata.update(node.metadata)
            return existing

        self._nodes[node.id] = node
        return node

    def get_node(self, node_id: str) -> Optional[Node]:
        """Retrieve node by ID."""
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        """Check if node exists in graph."""
        return node_id in self._nodes

    def add_edge(self, edge: Edge) -> bool:
        """Add an edge to the graph if it is not a duplicate.

        Returns True if added, False if duplicate.
        """
        key = edge.identity_key()
        if key in self._edge_keys:
            return False

        self._edge_keys.add(key)
        self._edges.append(edge)
        self._out_edges.setdefault(edge.source, []).append(edge)
        return True

    def outgoing(self, source: str) -> List[Edge]:
        """Edges leaving ``source`` (O(1) lookup via the adjacency index)."""
        return self._out_edges.get(source, [])

    def get_edges(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        edge_type: Optional[str] = None,
        effect: Optional[str] = None,
    ) -> List[Edge]:
        """Query edges by optional filters."""
        results = []
        candidates = self._out_edges.get(source, []) if source is not None else self._edges
        for edge in candidates:
            if source is not None and edge.source != source:
                continue
            if target is not None and edge.target != target:
                continue
            if edge_type is not None and edge.edge_type != edge_type:
                continue
            if effect is not None and edge.effect != effect:
                continue
            results.append(edge)
        return results

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire graph to a structured dictionary."""
        # Sort nodes deterministically by ID
        sorted_nodes = [
            self._nodes[node_id].to_dict()
            for node_id in sorted(self._nodes.keys())
        ]
        # Sort edges deterministically by source, target, edge_type, effect
        sorted_edges = [
            edge.to_dict()
            for edge in sorted(
                self._edges,
                key=lambda e: (e.source, e.target, e.edge_type, e.effect, e.actions),
            )
        ]
        return {
            "scenario_id": self.scenario_id,
            "nodes": sorted_nodes,
            "edges": sorted_edges,
        }
