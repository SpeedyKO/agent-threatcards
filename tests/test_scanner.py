import json
import tempfile
from pathlib import Path
from unittest import TestCase

from agent_threatcards import scan


class ScannerTests(TestCase):
    def test_flags_risky_mcp_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "github": {"command": "npx", "env": {"GITHUB_TOKEN": "example-token"}},
                    "browser": {"command": "bash", "args": ["start.sh", "--allow-all"]},
                }
            }), encoding="utf-8")

            report = scan(root)

        rules = {finding.rule for finding in report.findings}
        self.assertIn("shell-command", rules)
        self.assertIn("dangerous-arg", rules)
        self.assertIn("literal-secret-env", rules)
        self.assertGreaterEqual(report.risk_score, 70)
