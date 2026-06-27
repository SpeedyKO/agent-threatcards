# agent-threatcards

[![test](https://github.com/SpeedyKO/agent-threatcards/actions/workflows/test.yml/badge.svg)](https://github.com/SpeedyKO/agent-threatcards/actions/workflows/test.yml)

`agent-threatcards` turns MCP and AI agent repository risks into short, reviewable threat cards.

It is built for developers shipping agents with OpenAI Agents SDK, MCP servers, LangGraph, CrewAI, browser tools, GitHub tools, filesystem tools, and other tool-using AI systems.

## Why This Exists

AI agent projects are moving from demos to real workflows. The risky part is rarely a single bad line of code. It is the combination of:

- private data access
- untrusted input
- tools that can send data elsewhere
- shell commands or broad local permissions
- secrets sitting in configs

`agent-threatcards` scans a repo locally and prints the risks as human-readable cards: what was found, why it matters, and the smallest fix.

## Install

```bash
python -m pip install .
```

## Usage

Scan a repository:

```bash
agent-threatcards .
```

Scan an MCP config:

```bash
agent-threatcards examples/risky-mcp.json
```

JSON output for CI:

```bash
agent-threatcards . --json
```

SARIF output for GitHub code scanning:

```bash
agent-threatcards . --sarif > agent-threatcards.sarif
```

Create a baseline for known findings:

```bash
agent-threatcards . --write-baseline agent-threatcards.baseline.json
```

Fail only on new findings:

```bash
agent-threatcards . --baseline agent-threatcards.baseline.json
```

Set up a repo with a baseline and GitHub Code Scanning workflow:

```bash
agent-threatcards init
```

Explain a rule:

```bash
agent-threatcards explain lethal-trifecta
```

## Example

```text
# Agent Threat Cards

Risk score: **100/100**

## HIGH: MCP server `browser` needs review

- Rule: `shell-command`
- Evidence: starts through `bash`
- Fix: wrap the server in a fixed command or remove shell execution
```

## Current Checks

- MCP servers launched through shells
- dangerous broad permission flags
- inline secret-like environment values
- prompt injection phrases in repo text
- data access + untrusted input + external send combinations

## GitHub Code Scanning

Use SARIF output when you want findings to show up in GitHub's Security tab:

```yaml
name: agent-threatcards

on:
  push:
  pull_request:

permissions:
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
      - run: agent-threatcards . --sarif > agent-threatcards.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agent-threatcards.sarif
```

If your repo already has accepted findings, add `--baseline agent-threatcards.baseline.json` to the scan command.

## Safety And Privacy

The scanner is local-first. It does not call model APIs, upload repository contents, install dependencies, or execute MCP servers.

This is not a vulnerability scanner or compliance product. It is a lightweight threat modeling tool for catching obvious agent-risk combinations before a repo, demo, or customer workflow goes live.

## Documentation

- [Rule catalog](docs/rules.md)
- [Baseline workflow](docs/baseline.md)
- [Design principles](docs/design.md)

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
