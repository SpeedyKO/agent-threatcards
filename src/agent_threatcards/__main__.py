from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bootstrap import init_project
from .scanner import scan


def _load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item.get("fingerprint")) for item in data.get("findings", []) if isinstance(item, dict)}


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        return _init(sys.argv[2:])

    parser = argparse.ArgumentParser(
        description="Generate threat cards for MCP and AI agent repos.",
        epilog="Command: agent-threatcards init [path] creates a baseline and GitHub Code Scanning workflow.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument("--sarif", action="store_true", help="Print SARIF 2.1.0 for GitHub code scanning.")
    parser.add_argument("--baseline", type=Path, help="Ignore findings already recorded in a baseline file.")
    parser.add_argument("--write-baseline", type=Path, help="Write the current findings as a baseline file.")
    args = parser.parse_args()

    report = scan(Path(args.path))
    if args.write_baseline:
        args.write_baseline.write_text(json.dumps(report.to_baseline(), indent=2) + "\n", encoding="utf-8")
    if args.baseline:
        report = report.without_fingerprints(_load_baseline(args.baseline))

    if args.sarif:
        print(json.dumps(report.to_sarif(), indent=2))
    elif args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_markdown())
    return 1 if report.risk_score >= 70 else 0


def _init(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Add agent-threatcards baseline and GitHub workflow.")
    parser.add_argument("path", nargs="?", default=".", help="Repository path to initialize.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files.")
    args = parser.parse_args(argv)

    try:
        workflow, baseline = init_project(Path(args.path), args.force)
    except FileExistsError as error:
        print(f"{error.filename} already exists; rerun with --force to overwrite", file=sys.stderr)
        return 2
    print(f"created {workflow}")
    print(f"created {baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
