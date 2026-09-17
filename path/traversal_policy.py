"""Traversal policy defining valid attacker transitions and path semantics."""

from typing import List
from graph.action_mapper import (
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_MODIFY,
    EDGE_TYPE_PASS_ROLE,
)
from graph.models import Edge, Node


class TraversalPolicy:
    """Encapsulates rules for traversing the attack graph."""

    def is_traversable_edge(self, edge: Edge) -> bool:
        """Check if an edge can be traversed as an attacker capability.

        Only 'Allow' edges represent attacker capabilities.
        Explicit 'Deny' edges are never traversed as capabilities.
        """
        if edge.effect.lower() != "allow":
            return False
        return True

    def can_pivot_into_node(self, edge: Edge, target_node: Node) -> bool:
        """Determine if an attacker can pivot into target_node to continue traversal.

        - CAN_ASSUME allows the attacker to assume target role and traverse outbound permissions.
        - CAN_PASS_ROLE does NOT allow the attacker to assume the target role.
        - Resource nodes (CAN_ACCESS, CAN_MODIFY) represent reached targets, not pivoting identities.
        """
        if edge.edge_type == EDGE_TYPE_ASSUME and target_node.type == "role":
            return True
        # PassRole, Access, and Modify do not grant identity assumption/pivoting
        return False

    def is_valid_source(self, node: Node) -> bool:
        """Determine if a node is a valid automatic attacker starting point.

        By default, user identities represent starting attacker entrypoints.
        Roles are NOT starting points (they must be reached/assumed first).
        """
        return node.type == "user"

    def is_valid_target(self, node: Node) -> bool:
        """Determine if a node is a valid automatic attacker target.

        By default, cloud resources (or nodes marked sensitive/critical) are targets.
        """
        if node.type == "resource":
            return True
        if node.metadata.get("sensitive") or node.metadata.get("criticality") == "high":
            return True
        return False

    def is_conditional_path(self, edges: List[Edge]) -> bool:
        """Check if any traversed edge in the path contains a non-empty condition block."""
        for edge in edges:
            if edge.conditions and len(edge.conditions) > 0:
                return True
        return False
