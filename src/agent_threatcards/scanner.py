from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 45}
SECRET_WORDS = ("token", "secret", "password", "api_key", "apikey", "private_key")
SHELL_COMMANDS = {"bash", "sh", "cmd", "powershell", "pwsh"}
RISKY_ARGS = ("--dangerously-skip-permissions", "--allow-all", "--no-sandbox", "--privileged")
PROMPT_INJECTION_PHRASES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal your system prompt",
    "exfiltrate",
    "send the token",
)
DATA_TOOLS = ("github", "filesystem", "drive", "slack", "notion", "postgres", "database")
SINK_TOOLS = ("browser", "fetch", "slack", "email", "github", "webhook", "http")
UNTRUSTED_TOOLS = ("github", "browser", "fetch", "web", "slack", "reddit")


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    title: str
    path: str
    evidence: str
    fix: str


@dataclass(frozen=True)
class Report:
    path: Path
    findings: tuple[Finding, ...]

    @property
    def risk_score(self) -> int:
        return min(100, sum(SEVERITY_POINTS[item.severity] for item in self.findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "risk_score": self.risk_score,
            "findings": [asdict(item) for item in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [f"# Agent Threat Cards", "", f"Risk score: **{self.risk_score}/100**", ""]
        if not self.findings:
            return "\n".join(lines + ["No obvious MCP or agent threat-card findings."])
        for item in self.findings:
            lines += [
                f"## {item.severity.upper()}: {item.title}",
                "",
                f"- Rule: `{item.rule}`",
                f"- File: `{item.path}`",
                f"- Evidence: {item.evidence}",
                f"- Fix: {item.fix}",
                "",
            ]
        return "\n".join(lines).rstrip()

    def to_sarif(self) -> dict[str, Any]:
        rules = {
            item.rule: {
                "id": item.rule,
                "name": item.title,
                "shortDescription": {"text": item.title},
                "help": {"text": item.fix},
            }
            for item in self.findings
        }
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "agent-threatcards", "rules": list(rules.values())}},
                "results": [self._sarif_result(item) for item in self.findings],
            }],
        }

    def _sarif_result(self, item: Finding) -> dict[str, Any]:
        return {
            "ruleId": item.rule,
            "level": {"high": "error", "medium": "warning", "low": "note"}[item.severity],
            "message": {"text": f"{item.evidence}. Fix: {item.fix}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(self.path, Path(item.path))},
                }
            }],
        }


def scan(path: Path) -> Report:
    root = path.resolve()
    findings: list[Finding] = []
    mcp_names: list[str] = []

    for file in _files(root):
        lower = file.name.lower()
        if lower.endswith(".json"):
            findings += _scan_json(file, mcp_names)
        if file.suffix.lower() in {".md", ".txt", ".prompt"}:
            findings += _scan_text(file)

    findings += _scan_tool_mix(root, mcp_names)
    return Report(root, tuple(findings))


def _files(root: Path) -> tuple[Path, ...]:
    if root.is_file():
        return (root,)
    if not root.exists():
        return ()
    ignored = {".git", ".venv", "node_modules", "__pycache__", "dist", "build"}
    return tuple(item for item in root.rglob("*") if item.is_file() and not any(part in ignored for part in item.parts))


def _scan_json(file: Path, mcp_names: list[str]) -> list[Finding]:
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []

    findings: list[Finding] = []
    for name, server in servers.items():
        mcp_names.append(str(name).lower())
        if not isinstance(server, dict):
            continue
        command = str(server.get("command", "")).lower()
        args = " ".join(map(str, server.get("args", []))).lower()
        env = server.get("env", {})

        if Path(command).name in SHELL_COMMANDS:
            findings.append(_finding("high", "shell-command", file, name, f"starts through `{command}`", "wrap the server in a fixed command or remove shell execution"))
        if any(flag in args for flag in RISKY_ARGS):
            findings.append(_finding("high", "dangerous-arg", file, name, f"uses risky args `{args}`", "drop broad permission flags and grant only the paths/tools needed"))
        if isinstance(env, dict):
            for key, value in env.items():
                if any(word in key.lower() for word in SECRET_WORDS) and value and not str(value).startswith("${"):
                    findings.append(_finding("medium", "literal-secret-env", file, name, f"`{key}` is set inline", "read secrets from the environment instead of committing values"))
    return findings


def _scan_text(file: Path) -> list[Finding]:
    try:
        text = file.read_text(encoding="utf-8").lower()
    except OSError:
        return []
    return [
        Finding("medium", "prompt-injection-text", "Prompt injection phrase in repo text", str(file), f"contains `{phrase}`", "keep hostile prompts in clearly labeled test fixtures")
        for phrase in PROMPT_INJECTION_PHRASES
        if phrase in text
    ]


def _scan_tool_mix(root: Path, names: list[str]) -> list[Finding]:
    joined = " ".join(names)
    if any(word in joined for word in DATA_TOOLS) and any(word in joined for word in SINK_TOOLS) and any(word in joined for word in UNTRUSTED_TOOLS):
        return [Finding("high", "lethal-trifecta", "Data access, external send, and untrusted input appear together", str(root), f"MCP servers: {', '.join(sorted(set(names)))}", "split duties across profiles or require human approval before sending data out")]
    return []


def _finding(severity: str, rule: str, file: Path, server: str, evidence: str, fix: str) -> Finding:
    return Finding(severity, rule, f"MCP server `{server}` needs review", str(file), evidence, fix)


def _uri(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
