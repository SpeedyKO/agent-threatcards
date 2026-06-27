from __future__ import annotations

import json
from pathlib import Path

from .scanner import scan


WORKFLOW = """name: agent-threatcards

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install git+https://github.com/SpeedyKO/agent-threatcards.git
      - run: agent-threatcards . --baseline agent-threatcards.baseline.json --sarif > agent-threatcards.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-threatcards.sarif
      - run: agent-threatcards . --baseline agent-threatcards.baseline.json
"""


def init_project(path: Path, force: bool = False) -> tuple[Path, Path]:
    root = path.resolve()
    workflow = root / ".github" / "workflows" / "agent-threatcards.yml"
    baseline = root / "agent-threatcards.baseline.json"

    for file in (workflow, baseline):
        if file.exists() and not force:
            raise FileExistsError(file)

    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(WORKFLOW, encoding="utf-8")
    baseline.write_text(json.dumps(scan(root).to_baseline(), indent=2) + "\n", encoding="utf-8")
    return workflow, baseline

