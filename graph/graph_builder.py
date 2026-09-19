"""Attack graph builder translating normalized IAM data into a directed graph."""

from typing import Any, Dict, List, Optional
from graph.action_mapper import (
    ActionMapper,
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_PASS_ROLE,
)
from graph.models import (
    DirectedAttackGraph,
    Edge,
    Node,
)
from graph.resource_matcher import ResourceMatcher


class GraphBuilder:
    """Constructs a DirectedAttackGraph from Phase 1 normalized IAM configuration."""

    def __init__(
        self,
        action_mapper: Optional[ActionMapper] = None,
        resource_matcher: Optional[ResourceMatcher] = None,
    ):
        self.action_mapper = action_mapper or ActionMapper()
        self.resource_matcher = resource_matcher or ResourceMatcher()

    def _resolve_principal_node(
        self, graph: DirectedAttackGraph, principal: str
    ) -> Node:
        """Resolve or synthesize a node for a trust policy principal."""
        principal = principal.strip()

        # Wildcard principal
        if principal == "*":
            node_id = "principal:*"
            if not graph.has_node(node_id):
                graph.add_node(
                    Node(
                        id=node_id,
                        type="principal",
                        name="*",
                        metadata={"synthetic": True, "source": "trust_policy_wildcard"},
                    )
                )
            return graph.get_node(node_id)

        # Check existing user, role, group
        if graph.has_node(f"user:{principal}"):
            return graph.get_node(f"user:{principal}")
        if graph.has_node(f"role:{principal}"):
            return graph.get_node(f"role:{principal}")
        if graph.has_node(f"group:{principal}"):
            return graph.get_node(f"group:{principal}")

        # Service principal (e.g. ec2.amazonaws.com, lambda.amazonaws.com)
        if principal.endswith(".amazonaws.com"):
            node_id = f"service:{principal}"
            if not graph.has_node(node_id):
                graph.add_node(
                    Node(
                        id=node_id,
                        type="service",
                        name=principal,
                        metadata={"synthetic": True, "source": "trust_policy_service"},
                    )
                )
            return graph.get_node(node_id)

        # External / uncataloged user/role/principal
        node_id = f"user:{principal}"
        if not graph.has_node(node_id):
            graph.add_node(
                Node(
                    id=node_id,
                    type="user",
                    name=principal,
                    metadata={"synthetic": True, "source": "trust_policy_principal"},
                )
            )
        return graph.get_node(node_id)

    def _classify_principal_type(self, node: Node) -> str:
        """Classify a resolved trust-policy principal node for downstream feature extraction.

        Returns one of: "wildcard", "service", "external", "internal".
        """
        if node.metadata.get("source") == "trust_policy_wildcard":
            return "wildcard"
        if node.type == "service":
            return "service"
        if node.metadata.get("source") == "trust_policy_principal":
            # Not declared among the scenario's own users/roles/groups -> external principal.
            return "external"
        return "internal"

    def _resolve_source_node(
        self, graph: DirectedAttackGraph, source_name: str
    ) -> Node:
        """Resolve entity holding permissions."""
        source_name = source_name.strip()
        for prefix in ("role", "user", "group"):
            candidate_id = f"{prefix}:{source_name}"
            if graph.has_node(candidate_id):
                return graph.get_node(candidate_id)

        # If not already declared, create default role node
        node_id = f"role:{source_name}"
        if not graph.has_node(node_id):
            graph.add_node(
                Node(
                    id=node_id,
                    type="role",
                    name=source_name,
                    metadata={"synthetic": True, "source": "permission_source"},
                )
            )
        return graph.get_node(node_id)

    def build_graph(self, normalized_data: Dict[str, Any]) -> DirectedAttackGraph:
        """Build DirectedAttackGraph from normalized IAM dictionary.

        Args:
            normalized_data: Output dictionary from Phase 1 normalizer.

        Returns:
            Constructed and populated DirectedAttackGraph.
        """
        if not isinstance(normalized_data, dict):
            raise ValueError(f"Expected dict for normalized_data, got {type(normalized_data).__name__}")

        scenario_id = normalized_data.get("scenario_id", "unknown_scenario")
        graph = DirectedAttackGraph(scenario_id=scenario_id)

        # 1. Register declared entities as nodes (synthetic: False)
        entities = normalized_data.get("entities", [])
        for entity in entities:
            e_type = entity.get("type", "resource")
            e_name = entity.get("name", "")
            if not e_name:
                continue

            # If resource entity has resource_type == 'role' and role node exists, merge arn
            if e_type == "resource" and entity.get("resource_type") == "role" and graph.has_node(f"role:{e_name}"):
                existing_role = graph.get_node(f"role:{e_name}")
                if entity.get("arn") and not existing_role.arn:
                    existing_role.arn = entity.get("arn")
                continue

            node_id = f"{e_type}:{e_name}"
            node = Node(
                id=node_id,
                type=e_type,
                name=e_name,
                arn=entity.get("arn"),
                resource_type=entity.get("resource_type"),
                metadata={"synthetic": False},
            )
            graph.add_node(node)

        # 2. Process trust relationships -> CAN_ASSUME edges
        trust_rels = normalized_data.get("trust_relationships", [])
        for rel in trust_rels:
            source_raw = rel.get("source", "")
            target_role = rel.get("target", "")
            if not source_raw or not target_role:
                continue

            source_node = self._resolve_principal_node(graph, source_raw)
            target_node_id = f"role:{target_role}"

            # If target role doesn't exist yet, synthesize it
            if not graph.has_node(target_node_id):
                graph.add_node(
                    Node(
                        id=target_node_id,
                        type="role",
                        name=target_role,
                        metadata={"synthetic": True, "source": "trust_policy_target"},
                    )
                )

            edge_metadata: Dict[str, Any] = {
                "origin": "trust_policy",
                "principal_type": self._classify_principal_type(source_node),
            }
            trust_actions = rel.get("actions", ["sts:AssumeRole"])
            if "*" in trust_actions:
                edge_metadata["action_scope"] = "wildcard"
                edge_metadata["broad_permission"] = True
            elif any(a.endswith(":*") for a in trust_actions):
                edge_metadata["action_scope"] = "service_wildcard"
                edge_metadata["broad_permission"] = True

            edge = Edge(
                source=source_node.id,
                target=target_node_id,
                edge_type=EDGE_TYPE_ASSUME,
                effect=rel.get("effect", "Allow"),
                actions=trust_actions,
                resources=[],
                conditions=rel.get("conditions", {}),
                metadata=edge_metadata,
            )
            graph.add_edge(edge)

        # 3. Process permissions -> permission edges
        permissions = normalized_data.get("permissions", [])
        for perm in permissions:
            source_name = perm.get("source", "")
            if not source_name:
                continue

            source_node = self._resolve_source_node(graph, source_name)
            effect = perm.get("effect", "Allow")
            raw_actions = perm.get("actions", [])
            raw_resources = perm.get("resources", [])
            conditions = perm.get("conditions", {})

            # Group actions by conceptual edge type
            grouped_actions = self.action_mapper.group_actions_by_edge_type(raw_actions)

            for edge_type, type_actions in grouped_actions.items():
                # Prepare edge metadata
                edge_metadata = {"origin": "permission"}
                if "*" in type_actions:
                    edge_metadata["action_scope"] = "wildcard"
                    edge_metadata["broad_permission"] = True
                elif any(a.endswith(":*") for a in type_actions):
                    edge_metadata["action_scope"] = "service_wildcard"
                    edge_metadata["broad_permission"] = True

                for res_pattern in raw_resources:
                    # Collect candidate nodes for matching
                    candidate_nodes = list(graph.nodes.values())
                    matching_nodes = self.resource_matcher.find_matching_nodes(
                        resource_pattern=res_pattern,
                        nodes=candidate_nodes,
                        edge_type=edge_type,
                    )

                    # If no known node matches, handle non-existent resource reference
                    if not matching_nodes:
                        # If action is assume role, create synthetic role node
                        if edge_type in (EDGE_TYPE_ASSUME, EDGE_TYPE_PASS_ROLE):
                            role_name = self.resource_matcher._extract_role_name_from_arn(res_pattern) or res_pattern
                            target_node_id = f"role:{role_name}"
                            target_node = Node(
                                id=target_node_id,
                                type="role",
                                name=role_name,
                                arn=res_pattern if ":role/" in res_pattern else None,
                                metadata={"synthetic": True, "source": "permission_resource"},
                            )
                        else:
                            target_node_id = f"resource:{res_pattern}"
                            target_node = Node(
                                id=target_node_id,
                                type="resource",
                                name=res_pattern,
                                arn=res_pattern,
                                metadata={"synthetic": True, "source": "permission_resource"},
                            )

                        graph.add_node(target_node)
                        matching_nodes = [target_node]

                    for target_node in matching_nodes:
                        edge = Edge(
                            source=source_node.id,
                            target=target_node.id,
                            edge_type=edge_type,
                            effect=effect,
                            actions=type_actions,
                            resources=raw_resources,
                            conditions=conditions,
                            metadata=edge_metadata.copy(),
                        )
                        graph.add_edge(edge)

        return graph

        return graph


def build_attack_graph(normalized_data: Dict[str, Any]) -> DirectedAttackGraph:
    """Convenience function to build attack graph from normalized data."""
    builder = GraphBuilder()
    return builder.build_graph(normalized_data)
