import json
import tempfile
from pathlib import Path
from unittest import TestCase

from agent_threatcards.bootstrap import init_project
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

    def test_sarif_contains_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text(json.dumps({
                "mcpServers": {"browser": {"command": "bash"}}
            }), encoding="utf-8")

            sarif = scan(root).to_sarif()

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "shell-command")
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "mcp.json",
        )
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1,
        )

    def test_baseline_filters_existing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text(json.dumps({
                "mcpServers": {"browser": {"command": "bash"}}
            }), encoding="utf-8")

            report = scan(root)
            fingerprints = {report.to_dict()["findings"][0]["fingerprint"]}

        self.assertEqual(report.without_fingerprints(fingerprints).findings, ())

    def test_init_project_writes_workflow_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text(json.dumps({
                "mcpServers": {"browser": {"command": "bash"}}
            }), encoding="utf-8")

            workflow, baseline = init_project(root)

            self.assertTrue(workflow.exists())
            self.assertIn("upload-sarif", workflow.read_text(encoding="utf-8"))
            self.assertEqual(
                json.loads(baseline.read_text(encoding="utf-8"))["findings"][0]["rule"],
                "shell-command",
            )
