# Rule Catalog

`agent-threatcards` uses small, explainable rules. Every finding should have evidence and a fix a developer can act on in one review.

List rules from the CLI:

```bash
agent-threatcards explain --list
```

Explain one rule:

```bash
agent-threatcards explain lethal-trifecta
```

## `shell-command`

Flags MCP servers launched through shells such as `bash`, `sh`, `cmd`, `powershell`, or `pwsh`.

Why it matters: shell wrappers blur what command actually runs and make injection, path confusion, and local environment surprises easier.

Fix: launch a fixed executable directly, or wrap the server in a tiny reviewed script with narrow inputs.

## `dangerous-arg`

Flags broad permission flags such as `--allow-all`, `--no-sandbox`, `--privileged`, and `--dangerously-skip-permissions`.

Why it matters: agents combine model output with tools. Broad local permissions turn ordinary prompt mistakes into system-level actions.

Fix: grant only the directories, tools, and network targets the workflow needs.

## `literal-secret-env`

Flags secret-like environment keys with committed literal values.

Why it matters: MCP configs are often copied into repos, issues, chats, and docs. Literal credentials spread quickly.

Fix: use environment placeholders such as `${GITHUB_TOKEN}` and keep real values in the user's environment or secret store.

## `prompt-injection-text`

Flags known prompt-injection phrases in repo text.

Why it matters: hostile prompts are valid test material, but they should be clearly labeled so agents and reviewers do not confuse them with operational instructions.

Fix: keep hostile prompts under test fixtures or docs that explicitly mark them as examples.

## `lethal-trifecta`

Flags the combination of data access, untrusted input, and external send capability in one agent profile.

Why it matters: this is where agent risk becomes practical: the agent can read sensitive context, ingest hostile instructions, and send data somewhere else.

Fix: split duties across profiles, remove one leg of the combination, or require human approval before outbound actions.
