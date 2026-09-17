"""Bounded cycle-safe path finder for discovering simple attack paths."""

from typing import List, Optional, Set
from graph.models import DirectedAttackGraph, Edge
from path.models import AttackPath
from path.traversal_policy import TraversalPolicy


class PathFinder:
    """Finds valid simple attack paths through a DirectedAttackGraph."""

    def __init__(self, policy: Optional[TraversalPolicy] = None):
        self.policy = policy or TraversalPolicy()

    def find_paths(
        self,
        graph: DirectedAttackGraph,
        source: Optional[str] = None,
        target: Optional[str] = None,
        max_hops: int = 5,
    ) -> List[AttackPath]:
        """Find all valid simple attack paths satisfying constraints.

        Args:
            graph: DirectedAttackGraph to traverse.
            source: Optional specific source node ID. If None, auto-discovers valid sources.
            target: Optional specific target node ID. If None, auto-discovers valid targets.
            max_hops: Maximum number of hops (edges) allowed in a path (default 5).

        Returns:
            List of AttackPath objects discovered.
        """
        # 1. Determine starting sources
        if source:
            if not graph.has_node(source):
                return []
            sources = [source]
        else:
            sources = [
                node.id
                for node in sorted(graph.nodes.values(), key=lambda n: n.id)
                if self.policy.is_valid_source(node)
            ]

        # 2. Determine target nodes
        if target:
            target_ids: Set[str] = {target}
        else:
            target_ids = {
                node.id
                for node in graph.nodes.values()
                if self.policy.is_valid_target(node)
            }

        discovered_paths: List[AttackPath] = []
        path_counter = 1

        # 3. Perform bounded DFS from each source
        for start_node in sources:
            paths_from_source = self._dfs_find(
                graph=graph,
                current_node=start_node,
                target_ids=target_ids,
                visited_nodes={start_node},
                current_node_path=[start_node],
                current_edge_path=[],
                max_hops=max_hops,
            )

            for node_path, edge_path in paths_from_source:
                path_id = f"{graph.scenario_id}_path_{path_counter:03d}"
                path_counter += 1

                edge_dicts = [e.to_dict() for e in edge_path]
                edge_types = [e.edge_type for e in edge_path]
                is_cond = self.policy.is_conditional_path(edge_path)

                attack_path = AttackPath(
                    path_id=path_id,
                    scenario_id=graph.scenario_id,
                    source=node_path[0],
                    target=node_path[-1],
                    nodes=node_path,
                    edges=edge_dicts,
                    hop_count=len(edge_path),
                    conditional=is_cond,
                    edge_types=edge_types,
                )
                discovered_paths.append(attack_path)

        return discovered_paths

    def _dfs_find(
        self,
        graph: DirectedAttackGraph,
        current_node: str,
        target_ids: Set[str],
        visited_nodes: Set[str],
        current_node_path: List[str],
        current_edge_path: List[Edge],
        max_hops: int,
    ) -> List[tuple]:
        """Recursive cycle-safe bounded DFS."""
        results: List[tuple] = []
        current_hops = len(current_edge_path)

        if current_hops >= max_hops:
            return results

        # Get outbound edges from current_node, sorted deterministically
        outbound_edges = list(graph.get_edges(source=current_node))
        # If current_node is a user, they can also leverage wildcard trust policies (principal:*)
        if current_node.startswith("user:"):
            for we in graph.get_edges(source="principal:*", edge_type="CAN_ASSUME"):
                synthesized_edge = Edge(
                    source=current_node,
                    target=we.target,
                    edge_type=we.edge_type,
                    effect=we.effect,
                    actions=we.actions,
                    resources=we.resources,
                    conditions=we.conditions,
                    metadata=we.metadata,
                )
                outbound_edges.append(synthesized_edge)

        sorted_edges = sorted(
            outbound_edges,
            key=lambda e: (e.target, e.edge_type, e.effect, e.actions),
        )

        for edge in sorted_edges:
            if not self.policy.is_traversable_edge(edge):
                continue

            next_node_id = edge.target
            if next_node_id in visited_nodes:
                # Cycle prevention for simple paths
                continue

            next_node = graph.get_node(next_node_id)
            if not next_node:
                continue

            new_node_path = current_node_path + [next_node_id]
            new_edge_path = current_edge_path + [edge]

            # If next_node matches a target, record path
            if next_node_id in target_ids:
                results.append((new_node_path, new_edge_path))

            # If policy allows pivoting into next_node, continue DFS
            if self.policy.can_pivot_into_node(edge, next_node):
                sub_results = self._dfs_find(
                    graph=graph,
                    current_node=next_node_id,
                    target_ids=target_ids,
                    visited_nodes=visited_nodes | {next_node_id},
                    current_node_path=new_node_path,
                    current_edge_path=new_edge_path,
                    max_hops=max_hops,
                )
                results.extend(sub_results)

        return results


def find_attack_paths(
    graph: DirectedAttackGraph,
    source: Optional[str] = None,
    target: Optional[str] = None,
    max_hops: int = 5,
    policy: Optional[TraversalPolicy] = None,
) -> List[AttackPath]:
    """Convenience function to find attack paths in a graph."""
    finder = PathFinder(policy=policy)
    return finder.find_paths(
        graph=graph,
        source=source,
        target=target,
        max_hops=max_hops,
    )
