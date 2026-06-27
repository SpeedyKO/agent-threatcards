from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import scan


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate threat cards for MCP and AI agent repos.")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument("--sarif", action="store_true", help="Print SARIF 2.1.0 for GitHub code scanning.")
    args = parser.parse_args()

    report = scan(Path(args.path))
    if args.sarif:
        print(json.dumps(report.to_sarif(), indent=2))
    elif args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_markdown())
    return 1 if report.risk_score >= 70 else 0


if __name__ == "__main__":
    raise SystemExit(main())
