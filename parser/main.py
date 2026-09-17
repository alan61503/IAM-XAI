"""Command-line interface for the IAM Configuration Parser and Normalizer."""

import argparse
import json
import sys
from pathlib import Path

from parser.normalizer import normalize_scenario_file
from parser.policy_parser import IAMValidationError


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m parser.main",
        description="Parse and normalize synthetic IAM configuration JSON files.",
    )
    parser.add_argument(
        "scenario_file",
        help="Path to the synthetic IAM scenario JSON file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output file path to save normalized JSON. If omitted, prints to stdout.",
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
        0 on success, 1 on validation/processing error.
    """
    arg_parser = build_arg_parser()
    parsed_args = arg_parser.parse_args(args)

    try:
        normalized_data = normalize_scenario_file(parsed_args.scenario_file)
        formatted_json = json.dumps(normalized_data, indent=parsed_args.indent)

        if parsed_args.output:
            output_path = Path(parsed_args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(formatted_json)
                f.write("\n")
            print(f"[SUCCESS] Normalized scenario written to: {output_path}")
        else:
            print(formatted_json)

        return 0

    except IAMValidationError as e:
        print(f"[VALIDATION ERROR] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
