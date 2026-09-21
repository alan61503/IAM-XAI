"""CLI entry point for Phase 8: Choke Point Detection.

Usage:
    python -m choke_point.main output/scenario_009_paths.json --output output/scenario_009_choke.json
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

from .choke_finder import identify_scenario_choke_points


def _load_json(file_path: Path) -> Any:
    """Load and parse a JSON file."""
    return json.loads(file_path.read_text(encoding="utf-8"))


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 8: Choke Point Detection")
    parser.add_argument(
        "input_paths",
        type=Path,
        help="Path to Phase 3 attack paths JSON file",
    )
    parser.add_argument(
        "--explanations",
        type=Path,
        default=None,
        help="Path to optional Phase 7 SHAP explanations JSON file",
    )
    parser.add_argument(
        "--predictions",
        type=Path,
        default=None,
        help="Path to optional Phase 6 ML predictions JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output file to write choke point detection results",
    )

    args = parser.parse_args(argv)

    try:
        data = _load_json(args.input_paths)
        paths = data.get("paths", data) if isinstance(data, dict) else data
        if not isinstance(paths, list):
            raise ValueError("Input paths must be a list or dict with 'paths' key.")
    except Exception as e:
        sys.stderr.write(f"Failed to read input paths file: {e}\n")
        return 1

    explanations = None
    if args.explanations and args.explanations.exists():
        try:
            explanations = _load_json(args.explanations)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load explanations file: {e}\n")

    predictions = None
    if args.predictions and args.predictions.exists():
        try:
            predictions = _load_json(args.predictions)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load predictions file: {e}\n")

    try:
        choke_points = identify_scenario_choke_points(paths, explanations, predictions)
        result = {
            "total_choke_points": len(choke_points),
            "top_choke_point": choke_points[0] if choke_points else None,
            "choke_points": choke_points,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Successfully wrote {len(choke_points)} choke points to {args.output}")
    except Exception as e:
        sys.stderr.write(f"Failed during choke point detection: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
