"""CLI entry point for Phase 9: Remediation Engine.

Usage:
    python -m remediation.main data/scenarios/scenario_009.json output/scenario_009_choke.json --output output/scenario_009_remediation.json
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

from .diff_generator import generate_policy_diff, generate_remediation_playbook
from .policy_remediator import remediate_choke_point
from .simulator import verify_remediation


def _load_json(file_path: Path) -> Any:
    """Load and parse a JSON file."""
    return json.loads(file_path.read_text(encoding="utf-8"))


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 9: Remediation Engine")
    parser.add_argument(
        "scenario_json",
        type=Path,
        help="Path to raw input scenario JSON file",
    )
    parser.add_argument(
        "choke_points_json",
        type=Path,
        help="Path to Phase 8 choke points JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write remediation output JSON file",
    )
    parser.add_argument(
        "--playbook-output",
        type=Path,
        default=None,
        help="Path to write markdown remediation playbook file",
    )

    args = parser.parse_args(argv)

    try:
        scenario = _load_json(args.scenario_json)
        choke_data = _load_json(args.choke_points_json)
    except Exception as e:
        sys.stderr.write(f"Failed to read input files: {e}\n")
        return 1

    choke_points = choke_data.get("choke_points", []) if isinstance(choke_data, dict) else choke_data
    if not choke_points:
        sys.stderr.write("No choke points found in input file.\n")
        return 1

    top_choke = choke_points[0]

    try:
        remediated_scenario, summary = remediate_choke_point(scenario, top_choke)
        diff = generate_policy_diff(scenario, remediated_scenario)
        verification = verify_remediation(scenario, remediated_scenario)

        playbook_text = generate_remediation_playbook(top_choke, summary, verification)

        result = {
            "scenario_id": scenario.get("scenario_id", ""),
            "top_choke_point": top_choke,
            "remediation_summary": summary,
            "policy_diff": diff,
            "verification": verification,
            "remediated_scenario": remediated_scenario,
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Successfully wrote remediation results to {args.output}")

        if args.playbook_output:
            args.playbook_output.parent.mkdir(parents=True, exist_ok=True)
            args.playbook_output.write_text(playbook_text, encoding="utf-8")
            print(f"Successfully wrote playbook to {args.playbook_output}")

    except Exception as e:
        sys.stderr.write(f"Failed during remediation execution: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
