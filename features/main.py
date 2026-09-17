"""Command‑line interface for Phase 4 feature extraction.

Usage example::

    python -m features.main path_output.json --output features.json
    python -m features.main path_output.json --format csv --output features.csv

The script reads a JSON file containing the Phase‑3 path list, extracts
features for each path using :func:`features.feature_extractor.extract_features`
and writes the results either as a dataset‑style JSON file or as a CSV
file.  All operations are deterministic – the order of records follows
the order in the input file, and feature columns follow the ordering
defined in ``feature_schema.FEATURE_NAMES``.
"""

import argparse
import json
from pathlib import Path
import sys

from .feature_extractor import extract_features
from .feature_serializer import to_json, to_csv


def _load_paths(input_path: Path):
    """Load the Phase‑3 path JSON.

    The file may contain either a single dictionary with a ``paths`` list
    or a list of path dictionaries directly.  The function returns a list
    of path dicts.
    """
    data = json.loads(input_path.read_text())
    if isinstance(data, dict) and "paths" in data:
        return data["paths"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported input format for path JSON")


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 4 feature extraction")
    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to the Phase‑3 JSON file containing attack paths",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="File to write the extracted features",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args(argv)

    try:
        path_dicts = _load_paths(args.input_path)
    except Exception as e:
        sys.stderr.write(f"Failed to read input file: {e}\n")
        return 1

    records = []
    for pd in path_dicts:
        try:
            rec = extract_features(pd)
            records.append(rec)
        except Exception as e:
            sys.stderr.write(f"Error extracting features for path {pd.get('path_id')}: {e}\n")
            return 1

    try:
        if args.format == "json":
            to_json(records, args.output)
        else:
            to_csv(records, args.output)
    except Exception as e:
        sys.stderr.write(f"Failed to write output: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
