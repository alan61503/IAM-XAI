"""Decoupled path filtering layer for research experiments."""

from typing import List, Optional
from path.models import AttackPath


class PathFilter:
    """Filters discovered attack paths based on structural criteria."""

    def __init__(
        self,
        min_hops: Optional[int] = None,
        max_hops: Optional[int] = None,
        source: Optional[str] = None,
        target: Optional[str] = None,
        edge_types: Optional[List[str]] = None,
        conditional: Optional[bool] = None,
    ):
        self.min_hops = min_hops
        self.max_hops = max_hops
        self.source = source
        self.target = target
        self.edge_types = [et.upper() for et in edge_types] if edge_types else None
        self.conditional = conditional

    def matches(self, path: AttackPath) -> bool:
        """Evaluate if an AttackPath satisfies all filter conditions."""
        if self.min_hops is not None and path.hop_count < self.min_hops:
            return False

        if self.max_hops is not None and path.hop_count > self.max_hops:
            return False

        if self.source is not None and path.source != self.source:
            return False

        if self.target is not None and path.target != self.target:
            return False

        if self.conditional is not None and path.conditional != self.conditional:
            return False

        if self.edge_types is not None:
            # Check if path contains any of the specified edge_types
            path_types = {et.upper() for et in path.edge_types}
            if not any(req_et in path_types for req_et in self.edge_types):
                return False

        return True

    def filter_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Filter a list of attack paths."""
        return [p for p in paths if self.matches(p)]
