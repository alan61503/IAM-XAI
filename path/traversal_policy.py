"""Traversal policy defining valid attacker transitions and path semantics."""

from fnmatch import fnmatchcase
from typing import Dict, List, Tuple

from graph.action_mapper import (
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_MODIFY,
    EDGE_TYPE_PASS_ROLE,
)
from graph.models import DirectedAttackGraph, Edge, Node

# (source, target) -> [(denied action patterns, denied resource patterns), ...]
DenyIndex = Dict[Tuple[str, str], List[Tuple[List[str], List[str]]]]


def _covered(value: str, patterns: List[str]) -> bool:
    value = value.lower()
    return any(fnmatchcase(value, p) for p in patterns)


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

    def build_deny_index(self, graph: DirectedAttackGraph) -> DenyIndex:
        """Index unconditional explicit ``Deny`` edges by (source, target).

        Conditional denies are not indexed: whether they apply depends on
        request context the graph cannot know, so they are conservatively
        assumed not to protect the path (attacker-favorable assumption).
        """
        index: DenyIndex = {}
        for edge in graph.edges:
            if edge.effect.lower() == "deny" and not edge.conditions:
                entry = ([a.lower() for a in edge.actions], [r.lower() for r in edge.resources])
                index.setdefault((edge.source, edge.target), []).append(entry)
        return index

    def is_denied(self, edge: Edge, deny_index: DenyIndex) -> bool:
        """True when explicit denies remove every action this Allow edge grants.

        Explicit Deny overrides Allow (AWS policy evaluation logic). A deny only
        counts if it covers all of the Allow edge's resource patterns -- e.g.
        ``Deny s3:GetObject`` on ``bucket/secret/*`` does not block
        ``Allow s3:GetObject`` on ``bucket/*``. An action is removed when it
        matches a denied action pattern (``s3:*`` denies ``s3:GetObject``, but
        ``Deny s3:DeleteObject`` leaves the rest of ``Allow s3:*`` intact).
        """
        entries = deny_index.get((edge.source, edge.target))
        if not entries:
            return False
        denied_actions: List[str] = []
        for actions, resources in entries:
            if all(_covered(r, resources) for r in edge.resources):
                denied_actions.extend(actions)
        if not denied_actions:
            return False
        if not edge.actions:
            return "*" in denied_actions
        return all(_covered(a, denied_actions) for a in edge.actions)

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
