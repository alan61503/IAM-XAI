"""Serializer utilities for Phase 4 feature records.

Provides deterministic JSON and CSV output compatible with the feature
schema defined in ``feature_schema.py``.
"""

import csv
import json
from pathlib import Path
from typing import List, Dict, Any

from .feature_schema import FEATURE_SCHEMA_VERSION, FEATURE_NAMES


def to_json(records: List[Dict[str, Any]], output_path: Path) -> None:
    """Write ``records`` to *output_path* as a dataset‑style JSON file.

    The output structure matches the specification in the project
    documentation:

    .. code-block:: json

        {
            "scenario_id": "scenario_009",
            "feature_schema_version": "1.0",
            "records": [
                {"path_id": "...", "source": "...", "target": "...", "features": { ... }},
                ...
            ]
        }
    """
    if not records:
        raise ValueError("No records to serialize")

    # Assume all records belong to the same scenario – take from first.
    scenario_id = records[0].get("scenario_id")
    output_obj = {
        "scenario_id": scenario_id,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "records": records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output_obj, indent=2, sort_keys=False))


def to_csv(records: List[Dict[str, Any]], output_path: Path) -> None:
    """Write ``records`` to *output_path* as CSV.

    Columns are ordered as follows:

    1. ``scenario_id``
    2. ``path_id``
    3. ``source``
    4. ``target``
    5. all feature names from ``FEATURE_NAMES`` in the order defined.
    """
    if not records:
        raise ValueError("No records to serialize")

    header = ["scenario_id", "path_id", "source", "target"] + FEATURE_NAMES
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for rec in records:
            row = [
                rec.get("scenario_id"),
                rec.get("path_id"),
                rec.get("source"),
                rec.get("target"),
            ]
            feats = rec.get("features", {})
            row.extend(feats.get(name) for name in FEATURE_NAMES)
            writer.writerow(row)

__all__ = ["to_json", "to_csv"]
