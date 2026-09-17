"""Attack path data models for Phase 3."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AttackPath:
    """Represents an enumerated attack path through the directed attack graph."""
    path_id: str
    scenario_id: str
    source: str
    target: str
    nodes: List[str]
    edges: List[Dict[str, Any]]
    hop_count: int
    conditional: bool = False
    edge_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackPath to dictionary matching canonical schema."""
        return {
            "path_id": self.path_id,
            "scenario_id": self.scenario_id,
            "source": self.source,
            "target": self.target,
            "nodes": self.nodes,
            "edges": self.edges,
            "hop_count": self.hop_count,
            "conditional": self.conditional,
            "edge_types": self.edge_types,
        }
