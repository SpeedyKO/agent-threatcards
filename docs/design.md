# Design Principles

`agent-threatcards` is intentionally small.

## Local-first

The scanner does not call model APIs, upload repository contents, install dependencies, or execute MCP servers.

## Explainable Before Exhaustive

Each rule is easy to read and easy to challenge. A useful threat card beats a vague high score.

## Integration Over Dashboard

SARIF, JSON, Markdown, and baselines make the tool fit into existing developer workflows without hosting a service.

## Agent-specific Risk

The project focuses on risks created by tool-using AI systems: untrusted input, sensitive context, outbound actions, shell execution, and broad permissions.

