"""CLI entrypoint for Phase 2: Attack Graph Construction."""

import argparse
import json
import sys
from pathlib import Path

from graph.graph_builder import build_attack_graph
from graph.graph_serializer import serialize_graph_to_json, save_graph_file
from parser.normalizer import normalize_scenario_file


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m graph.main",
        description="Construct a directed attack graph from normalized IAM configuration JSON.",
    )
    parser.add_argument(
        "input_file",
        help="Path to the Phase 1 normalized JSON file (or raw scenario JSON file).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output file path to save graph JSON. If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation spaces (default: 2).",
    )
    return parser


def main(args: list = None) -> int:
    """Main CLI entrypoint.

    Returns:
        0 on success, 1 on processing error.
    """
    arg_parser = build_arg_parser()
    parsed_args = arg_parser.parse_args(args)

    input_path = Path(parsed_args.input_file)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Auto-detect if input is already normalized or raw scenario
        if "entities" in raw_data and "trust_relationships" in raw_data:
            normalized_data = raw_data
        else:
            normalized_data = normalize_scenario_file(input_path)

        # Build graph
        graph = build_attack_graph(normalized_data)

        # Output graph
        if parsed_args.output:
            save_graph_file(graph, parsed_args.output, indent=parsed_args.indent)
            print(f"[SUCCESS] Attack graph written to: {parsed_args.output}")
        else:
            print(serialize_graph_to_json(graph, indent=parsed_args.indent))

        return 0

    except Exception as e:
        print(f"[ERROR] Failed to construct attack graph: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
