"""Deterministic serialization and persistence for discovered attack paths."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from path.models import AttackPath


def serialize_paths_to_dict(
    paths: List[AttackPath],
    scenario_id: str = "",
    source_filter: Optional[str] = None,
    target_filter: Optional[str] = None,
    max_hops: int = 5,
) -> Dict[str, Any]:
    """Serialize paths into a deterministic dictionary."""
    # Deterministic sorting of paths
    sorted_paths = sorted(
        paths,
        key=lambda p: (p.source, p.target, p.hop_count, tuple(p.nodes), p.path_id),
    )

    return {
        "scenario_id": scenario_id or (paths[0].scenario_id if paths else ""),
        "source_filter": source_filter,
        "target_filter": target_filter,
        "max_hops": max_hops,
        "total_paths": len(sorted_paths),
        "paths": [p.to_dict() for p in sorted_paths],
    }


def serialize_paths_to_json(
    paths: List[AttackPath],
    scenario_id: str = "",
    source_filter: Optional[str] = None,
    target_filter: Optional[str] = None,
    max_hops: int = 5,
    indent: int = 2,
) -> str:
    """Serialize paths to a deterministic JSON string."""
    data = serialize_paths_to_dict(
        paths=paths,
        scenario_id=scenario_id,
        source_filter=source_filter,
        target_filter=target_filter,
        max_hops=max_hops,
    )
    return json.dumps(data, indent=indent)


def save_paths_file(
    paths: List[AttackPath],
    filepath: Union[str, Path],
    scenario_id: str = "",
    source_filter: Optional[str] = None,
    target_filter: Optional[str] = None,
    max_hops: int = 5,
    indent: int = 2,
) -> None:
    """Save serialized paths to a file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = serialize_paths_to_json(
        paths=paths,
        scenario_id=scenario_id,
        source_filter=source_filter,
        target_filter=target_filter,
        max_hops=max_hops,
        indent=indent,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_str)
        f.write("\n")


def deserialize_paths_from_dict(data: Dict[str, Any]) -> List[AttackPath]:
    """Reconstruct list of AttackPath objects from dictionary."""
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict for path data, got {type(data).__name__}")

    paths = []
    for item in data.get("paths", []):
        ap = AttackPath(
            path_id=item["path_id"],
            scenario_id=item.get("scenario_id", data.get("scenario_id", "")),
            source=item["source"],
            target=item["target"],
            nodes=item["nodes"],
            edges=item["edges"],
            hop_count=item["hop_count"],
            conditional=item.get("conditional", False),
            edge_types=item.get("edge_types", []),
        )
        paths.append(ap)
    return paths


def load_paths_file(filepath: Union[str, Path]) -> List[AttackPath]:
    """Load paths from a JSON file."""
    path = Path(filepath)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return deserialize_paths_from_dict(data)
