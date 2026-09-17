"""CLI entrypoint for Phase 3: Attack Path Detection."""

import argparse
import json
import sys
from pathlib import Path

from graph.graph_serializer import deserialize_graph_from_dict
from path.path_filter import PathFilter
from path.path_finder import PathFinder
from path.path_serializer import save_paths_file, serialize_paths_to_json


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m path.main",
        description="Detect and enumerate valid attack paths from a Phase 2 attack graph JSON.",
    )
    parser.add_argument(
        "graph_file",
        help="Path to the Phase 2 serialized attack graph JSON file.",
    )
    parser.add_argument(
        "-s",
        "--source",
        default=None,
        help="Optional starting attacker entity ID (e.g. user:InitialUser). If omitted, auto-discovers all user entities.",
    )
    parser.add_argument(
        "-t",
        "--target",
        default=None,
        help="Optional target entity ID (e.g. resource:ProductionDataBucket). If omitted, auto-discovers all resource entities.",
    )
    parser.add_argument(
        "--min-hops",
        type=int,
        default=None,
        help="Optional minimum hop count filter (e.g. 2 for multi-hop paths only).",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=5,
        help="Maximum hop count allowed in path enumeration (default: 5).",
    )
    parser.add_argument(
        "--edge-types",
        nargs="+",
        default=None,
        help="Optional filter for paths containing specific edge types (e.g. CAN_ASSUME CAN_ACCESS).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output file path to save paths JSON. If omitted, prints to stdout.",
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
        0 on success, 1 on error.
    """
    arg_parser = build_arg_parser()
    parsed_args = arg_parser.parse_args(args)

    graph_path = Path(parsed_args.graph_file)
    if not graph_path.exists():
        print(f"[ERROR] Graph file not found: {graph_path}", file=sys.stderr)
        return 1

    try:
        with open(graph_path, "r", encoding="utf-8") as f:
            graph_data = json.load(f)

        graph = deserialize_graph_from_dict(graph_data)

        # 1. Discover candidate paths using PathFinder
        finder = PathFinder()
        discovered_paths = finder.find_paths(
            graph=graph,
            source=parsed_args.source,
            target=parsed_args.target,
            max_hops=parsed_args.max_hops,
        )

        # 2. Apply decoupled PathFilter if filtering criteria provided
        if parsed_args.min_hops is not None or parsed_args.edge_types is not None:
            path_filter = PathFilter(
                min_hops=parsed_args.min_hops,
                max_hops=parsed_args.max_hops,
                source=parsed_args.source,
                target=parsed_args.target,
                edge_types=parsed_args.edge_types,
            )
            filtered_paths = path_filter.filter_paths(discovered_paths)
        else:
            filtered_paths = discovered_paths

        # 3. Output result
        if parsed_args.output:
            save_paths_file(
                paths=filtered_paths,
                filepath=parsed_args.output,
                scenario_id=graph.scenario_id,
                source_filter=parsed_args.source,
                target_filter=parsed_args.target,
                max_hops=parsed_args.max_hops,
                indent=parsed_args.indent,
            )
            print(f"[SUCCESS] Discovered {len(filtered_paths)} attack paths written to: {parsed_args.output}")
        else:
            json_str = serialize_paths_to_json(
                paths=filtered_paths,
                scenario_id=graph.scenario_id,
                source_filter=parsed_args.source,
                target_filter=parsed_args.target,
                max_hops=parsed_args.max_hops,
                indent=parsed_args.indent,
            )
            print(json_str)

        return 0

    except Exception as e:
        print(f"[ERROR] Failed to discover attack paths: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
