"""Resource ARN and pattern matching against graph nodes."""

import re
from typing import List, Optional
from graph.models import Node
from graph.action_mapper import EDGE_TYPE_ASSUME, EDGE_TYPE_PASS_ROLE


class ResourceMatcher:
    """Matches permission resource patterns against known attack graph nodes."""

    @staticmethod
    def _extract_bucket_arn_from_object_arn(arn: str) -> Optional[str]:
        """Convert 'arn:aws:s3:::bucket-name/*' or 'arn:aws:s3:::bucket-name/key' to 'arn:aws:s3:::bucket-name'."""
        if arn.startswith("arn:aws:s3:::"):
            remainder = arn[len("arn:aws:s3:::"):]
            parts = remainder.split("/", 1)
            bucket_name = parts[0]
            if bucket_name and bucket_name != "*":
                return f"arn:aws:s3:::{bucket_name}"
        return None

    @staticmethod
    def _extract_role_name_from_arn(arn: str) -> Optional[str]:
        """Extract role name from IAM role ARN e.g. 'arn:aws:iam::123456789012:role/RoleName'."""
        if ":role/" in arn:
            return arn.split(":role/", 1)[1]
        return None

    def matches(
        self,
        resource_pattern: str,
        node: Node,
        edge_type: str = "",
    ) -> bool:
        """Check if a resource pattern from a policy matches a candidate graph node.

        Args:
            resource_pattern: ARN or resource name from permission (e.g. 'arn:aws:s3:::my-bucket/*').
            node: Candidate Node to match against.
            edge_type: Conceptual edge type (e.g. 'CAN_ASSUME', 'CAN_ACCESS').

        Returns:
            True if pattern matches node, False otherwise.
        """
        pattern = resource_pattern.strip()
        pattern_lower = pattern.lower()

        # For role assumption and pass role, the target must be a role
        if edge_type in (EDGE_TYPE_ASSUME, EDGE_TYPE_PASS_ROLE) and node.type != "role":
            return False

        # 1. Full wildcard '*'
        if pattern == "*":
            if edge_type in (EDGE_TYPE_ASSUME, EDGE_TYPE_PASS_ROLE):
                return node.type == "role"
            return node.type == "resource"

        # 2. Exact match on ARN or Name
        if node.arn and pattern == node.arn:
            return True
        if pattern == node.name or pattern_lower == node.name.lower():
            return True

        # 3. Role ARN matching
        # e.g., resource is 'arn:aws:iam::123456789012:role/TargetRoleB'
        role_name = self._extract_role_name_from_arn(pattern)
        if role_name and node.type == "role":
            if node.name == role_name or (node.arn and pattern == node.arn):
                return True

        # 4. S3 Service Wildcard: 'arn:aws:s3:::*'
        if pattern in ("arn:aws:s3:::*", "arn:aws:s3:::*/*"):
            if node.resource_type == "s3" or (node.arn and node.arn.startswith("arn:aws:s3:::")):
                return True

        # 5. S3 Bucket / Object path matching
        # e.g. pattern 'arn:aws:s3:::example-bucket/*' matching node ARN 'arn:aws:s3:::example-bucket'
        bucket_arn = self._extract_bucket_arn_from_object_arn(pattern)
        if bucket_arn:
            if node.arn and bucket_arn == node.arn:
                return True
            # Also check if node.name is the bucket name
            bucket_name = bucket_arn.replace("arn:aws:s3:::", "")
            if node.name == bucket_name or node.name.lower() == bucket_name.lower():
                return True

        # 6. General ARN prefix with wildcard e.g. 'arn:aws:dynamodb:*:*:table/App*'
        if "*" in pattern:
            # Escape regex characters except '*'
            regex_str = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
            if node.arn and re.match(regex_str, node.arn):
                return True
            if re.match(regex_str, node.name):
                return True

        return False

    def find_matching_nodes(
        self,
        resource_pattern: str,
        nodes: List[Node],
        edge_type: str = "",
    ) -> List[Node]:
        """Find all nodes from candidate list that match the resource pattern."""
        return [
            node for node in nodes
            if self.matches(resource_pattern, node, edge_type=edge_type)
        ]
