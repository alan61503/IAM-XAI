"""Phase 7 CLI: export SHAP explanation JSON for one attack path or the whole dataset.

Usage::

    python -m explainability.export_explanation --path-id synthetic_00005_path_001
    python -m explainability.export_explanation --all --output evaluation/shap/explanations.json
"""

import argparse
import json
import sys
from pathlib import Path

from models.preprocess import load_dataset

from .explain_prediction import explain_path, explain_rows

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "evaluation" / "shap"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m explainability.export_explanation",
        description="Export SHAP explanation JSON for one or all attack paths.",
    )
    parser.add_argument("--input", default="data/processed/iam_attack_dataset.csv", help="Phase 5 dataset CSV.")
    parser.add_argument("--path-id", default=None, help="Export a single path's explanation.")
    parser.add_argument("--all", action="store_true", help="Export explanations for every path in the dataset.")
    parser.add_argument("--output", default=None, help="Output JSON file (defaults under evaluation/shap/).")
    return parser


def main(args: list = None) -> int:
    parsed = build_arg_parser().parse_args(args)

    if not parsed.path_id and not parsed.all:
        print("[ERROR] Provide --path-id or --all.", file=sys.stderr)
        return 1

    if parsed.path_id:
        payload = explain_path(parsed.path_id, dataset_path=parsed.input)
        default_output = DEFAULT_OUTPUT_DIR / f"{parsed.path_id}_explanation.json"
    else:
        df = load_dataset(parsed.input)
        payload = explain_rows(df)
        default_output = DEFAULT_OUTPUT_DIR / "explanations.json"

    output_path = Path(parsed.output) if parsed.output else default_output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))

    count = 1 if parsed.path_id else len(payload)
    print(f"[SUCCESS] Wrote {count} explanation(s) to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
