from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import scan


def _load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item.get("fingerprint")) for item in data.get("findings", []) if isinstance(item, dict)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate threat cards for MCP and AI agent repos.")
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


if __name__ == "__main__":
    raise SystemExit(main())
