"""CLI for Phase 5: generate the synthetic IAM attack-path dataset.

Usage::

    python -m dataset.main --count 1000 --output data/processed/iam_attack_dataset.csv
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

from .generator import generate_rows
from .schema import DATASET_COLUMNS


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dataset.main",
        description="Generate the Phase 5 synthetic IAM attack-path dataset.",
    )
    parser.add_argument("--count", type=int, default=1000, help="Number of synthetic scenarios to generate (default: 1000).")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42).")
    parser.add_argument("--output", required=True, help="Output CSV file path.")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    rows = generate_rows(count=parsed.count, seed=parsed.seed)
    if not rows:
        print("[ERROR] No attack paths were generated.", file=sys.stderr)
        return 1

    output_path = Path(parsed.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(rows, columns=DATASET_COLUMNS)
    df.to_csv(output_path, index=False)

    label_counts = Counter(df["risk_label"])
    print(f"[SUCCESS] Wrote {len(df)} attack paths from {parsed.count} scenarios to: {output_path}")
    print("Risk label distribution:")
    for label in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        print(f"  {label:>8}: {label_counts.get(label, 0)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
