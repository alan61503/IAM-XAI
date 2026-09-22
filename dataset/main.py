"""CLI for Phase 5: generate the synthetic IAM attack-path dataset.

Usage::

    python -m dataset.main --count 3000 --output data/processed/iam_attack_dataset.csv --workers 4
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from .generator import DEFAULT_MAX_PATHS_PER_SCENARIO, generate_rows
from .schema import DATASET_COLUMNS, DATASET_SCHEMA_VERSION, FEATURE_COLUMNS, RISK_LABELS


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dataset.main",
        description="Generate the Phase 5 synthetic IAM attack-path dataset.",
    )
    parser.add_argument("--count", type=int, default=1000, help="Number of synthetic environments to generate (default: 1000).")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42).")
    parser.add_argument("--output", required=True, help="Output CSV file path.")
    parser.add_argument(
        "--max-paths-per-scenario",
        type=int,
        default=DEFAULT_MAX_PATHS_PER_SCENARIO,
        help=f"Cap on attack paths kept per environment (default: {DEFAULT_MAX_PATHS_PER_SCENARIO}).",
    )
    parser.add_argument("--label-noise", type=float, default=0.0, help="Probability of shifting a label to an adjacent class (default: 0).")
    parser.add_argument("--workers", type=int, default=1, help="Parallel worker processes (default: 1). Output is identical for any value.")
    return parser


def dataset_report(df: pd.DataFrame, args: argparse.Namespace) -> dict:
    patterns = df.drop_duplicates("scenario_id")["scenario_patterns"].str.split("|").explode()
    return {
        "schema_version": DATASET_SCHEMA_VERSION,
        "seed": args.seed,
        "scenarios": int(df["scenario_id"].nunique()),
        "attack_paths": int(len(df)),
        "unique_feature_vectors": int(len(df[FEATURE_COLUMNS].drop_duplicates())),
        "label_distribution": {label: int((df["risk_label"] == label).sum()) for label in RISK_LABELS},
        "attack_type_distribution": df["attack_type"].value_counts().to_dict(),
        "target_classification_distribution": df["target_classification"].value_counts().to_dict(),
        "scenarios_per_injected_pattern": patterns.value_counts().to_dict(),
        "max_paths_per_scenario": args.max_paths_per_scenario,
        "label_noise": args.label_noise,
    }


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    rows = generate_rows(
        count=parsed.count,
        seed=parsed.seed,
        max_paths_per_scenario=parsed.max_paths_per_scenario,
        label_noise=parsed.label_noise,
        workers=parsed.workers,
    )
    if not rows:
        print("[ERROR] No attack paths were generated.", file=sys.stderr)
        return 1

    output_path = Path(parsed.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(rows, columns=DATASET_COLUMNS)
    df.to_csv(output_path, index=False)

    report = dataset_report(df, parsed)
    report_path = output_path.with_name(output_path.stem + "_report.json")
    report_path.write_text(json.dumps(report, indent=2))

    print(f"[SUCCESS] Wrote {len(df)} attack paths from {parsed.count} environments to: {output_path}")
    print(f"[SUCCESS] Dataset report written to: {report_path}")
    print("Risk label distribution:")
    for label in RISK_LABELS:
        print(f"  {label:>8}: {report['label_distribution'][label]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
