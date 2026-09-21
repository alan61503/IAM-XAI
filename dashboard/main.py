"""CLI launcher for Phase 10: Interactive Dashboard.

Usage:
    python -m dashboard.main --port 8000
"""

import argparse
import sys
from typing import List

from .server import run_dashboard_server


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 10: IAM-XAI Interactive Dashboard Launcher")
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the dashboard web server (default: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host address to bind the server (default: 0.0.0.0)",
    )

    args = parser.parse_args(argv)

    try:
        run_dashboard_server(port=args.port, host=args.host)
    except Exception as e:
        sys.stderr.write(f"Dashboard server error: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
