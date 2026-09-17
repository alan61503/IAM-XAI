"""Action classification layer mapping IAM actions and wildcards to conceptual edge types."""

import re
from typing import Dict, List, Set

# Conceptual Edge Types
EDGE_TYPE_ASSUME = "CAN_ASSUME"
EDGE_TYPE_ACCESS = "CAN_ACCESS"
EDGE_TYPE_PASS_ROLE = "CAN_PASS_ROLE"
EDGE_TYPE_MODIFY = "CAN_MODIFY"

ALL_EDGE_TYPES = [
    EDGE_TYPE_ASSUME,
    EDGE_TYPE_ACCESS,
    EDGE_TYPE_PASS_ROLE,
    EDGE_TYPE_MODIFY,
]


class ActionMapper:
    """Classifies AWS IAM actions into conceptual attack graph edge types."""

    def __init__(self):
        # Exact action mappings
        self._exact_mappings: Dict[str, Set[str]] = {
            # sts
            "sts:assumerole": {EDGE_TYPE_ASSUME},
            "sts:assumerolewithsaml": {EDGE_TYPE_ASSUME},
            "sts:assumerolewithwebidentity": {EDGE_TYPE_ASSUME},
            # iam
            "iam:passrole": {EDGE_TYPE_PASS_ROLE},
            # s3 read
            "s3:getobject": {EDGE_TYPE_ACCESS},
            "s3:getobjectversion": {EDGE_TYPE_ACCESS},
            "s3:getobjectacl": {EDGE_TYPE_ACCESS},
            "s3:listbucket": {EDGE_TYPE_ACCESS},
            "s3:listallmybuckets": {EDGE_TYPE_ACCESS},
            # s3 write / modify
            "s3:putobject": {EDGE_TYPE_MODIFY},
            "s3:putobjectacl": {EDGE_TYPE_MODIFY},
            "s3:deleteobject": {EDGE_TYPE_MODIFY},
            "s3:deleteobjectversion": {EDGE_TYPE_MODIFY},
            "s3:deletebucket": {EDGE_TYPE_MODIFY},
            "s3:createbucket": {EDGE_TYPE_MODIFY},
            # dynamodb
            "dynamodb:getitem": {EDGE_TYPE_ACCESS},
            "dynamodb:batchgetitem": {EDGE_TYPE_ACCESS},
            "dynamodb:query": {EDGE_TYPE_ACCESS},
            "dynamodb:scan": {EDGE_TYPE_ACCESS},
            "dynamodb:putitem": {EDGE_TYPE_MODIFY},
            "dynamodb:updateitem": {EDGE_TYPE_MODIFY},
            "dynamodb:deleteitem": {EDGE_TYPE_MODIFY},
            "dynamodb:batchwriteitem": {EDGE_TYPE_MODIFY},
            # secretsmanager
            "secretsmanager:getsecretvalue": {EDGE_TYPE_ACCESS},
            "secretsmanager:describesecret": {EDGE_TYPE_ACCESS},
            "secretsmanager:putsecretvalue": {EDGE_TYPE_MODIFY},
            "secretsmanager:createsecret": {EDGE_TYPE_MODIFY},
            "secretsmanager:deletesecret": {EDGE_TYPE_MODIFY},
            # sqs
            "sqs:receivemessage": {EDGE_TYPE_ACCESS},
            "sqs:sendmessage": {EDGE_TYPE_MODIFY},
            "sqs:deletemessage": {EDGE_TYPE_MODIFY},
            # ec2
            "ec2:describeinstances": {EDGE_TYPE_ACCESS},
            "ec2:terminateinstances": {EDGE_TYPE_MODIFY},
            "ec2:runinstances": {EDGE_TYPE_MODIFY},
        }

        # Prefix / pattern mappings
        self._prefix_mappings: List[tuple] = [
            # Assume role prefix
            ("sts:assume*", {EDGE_TYPE_ASSUME}),
            # Pass role
            ("iam:passrole*", {EDGE_TYPE_PASS_ROLE}),
            # Read prefixes
            ("*:get*", {EDGE_TYPE_ACCESS}),
            ("*:list*", {EDGE_TYPE_ACCESS}),
            ("*:describe*", {EDGE_TYPE_ACCESS}),
            ("*:scan*", {EDGE_TYPE_ACCESS}),
            ("*:query*", {EDGE_TYPE_ACCESS}),
            ("*:read*", {EDGE_TYPE_ACCESS}),
            ("*:receive*", {EDGE_TYPE_ACCESS}),
            # Write / modify prefixes
            ("*:put*", {EDGE_TYPE_MODIFY}),
            ("*:delete*", {EDGE_TYPE_MODIFY}),
            ("*:create*", {EDGE_TYPE_MODIFY}),
            ("*:update*", {EDGE_TYPE_MODIFY}),
            ("*:send*", {EDGE_TYPE_MODIFY}),
            ("*:write*", {EDGE_TYPE_MODIFY}),
            ("*:terminate*", {EDGE_TYPE_MODIFY}),
        ]

    def register_exact_mapping(self, action: str, edge_types: Set[str]) -> None:
        """Register a new exact action mapping."""
        self._exact_mappings[action.lower().strip()] = edge_types

    def register_prefix_mapping(self, pattern: str, edge_types: Set[str]) -> None:
        """Register a prefix/wildcard action pattern mapping."""
        self._prefix_mappings.append((pattern.lower().strip(), edge_types))

    def classify_action(self, action: str) -> Set[str]:
        """Classify a single AWS action into applicable conceptual edge types.

        Args:
            action: Action string (e.g. 's3:GetObject', 's3:*', '*').

        Returns:
            Set of edge type strings.
        """
        action_clean = action.strip()
        action_lower = action_clean.lower()

        # Full wildcard: conservatively maps to data access and modification.
        # sts:AssumeRole and iam:PassRole have strict operational semantics and
        # are NOT inferred merely from Action: "*".
        if action_lower == "*":
            return {
                EDGE_TYPE_ACCESS,
                EDGE_TYPE_MODIFY,
            }

        # Service-level wildcard e.g. "s3:*" or "dynamodb:*"
        if action_lower.endswith(":*"):
            service = action_lower.split(":", 1)[0]
            if service == "sts":
                return {EDGE_TYPE_ASSUME}
            if service == "iam":
                return {EDGE_TYPE_PASS_ROLE, EDGE_TYPE_MODIFY, EDGE_TYPE_ACCESS}
            # Standard data services grant both access (read) and modify (write)
            return {EDGE_TYPE_ACCESS, EDGE_TYPE_MODIFY}

        # Check exact mappings
        if action_lower in self._exact_mappings:
            return set(self._exact_mappings[action_lower])

        # Check pattern / prefix mappings
        matched_types: Set[str] = set()
        for pattern, types in self._prefix_mappings:
            regex_pattern = "^" + pattern.replace("*", ".*") + "$"
            if re.match(regex_pattern, action_lower):
                matched_types.update(types)

        if matched_types:
            return matched_types

        # Default fallback: if action is unrecognized, classify conservatively as CAN_ACCESS
        return {EDGE_TYPE_ACCESS}

    def group_actions_by_edge_type(
        self, actions: List[str]
    ) -> Dict[str, List[str]]:
        """Group list of actions by applicable edge type.

        An action that implies multiple capabilities (e.g., wildcards)
        will be included in each applicable group.

        Returns:
            Dictionary mapping edge_type -> list of original action strings.
        """
        grouped: Dict[str, List[str]] = {}
        for action in actions:
            edge_types = self.classify_action(action)
            for et in edge_types:
                if et not in grouped:
                    grouped[et] = []
                if action not in grouped[et]:
                    grouped[et].append(action)
        return grouped
