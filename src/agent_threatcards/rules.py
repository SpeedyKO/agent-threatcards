from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    risk: str
    why_agents: str
    fix: str

    def to_markdown(self) -> str:
        return "\n\n".join((
            f"# {self.id}",
            self.title,
            f"Risk: {self.risk}",
            f"Why this matters for agents: {self.why_agents}",
            f"Fix: {self.fix}",
        ))


RULES = {
    "shell-command": Rule(
        "shell-command",
        "MCP server is launched through a shell.",
        "Shell wrappers make the real execution boundary harder to review and can turn user-controlled strings into commands.",
        "Tool-using agents often combine model output, retrieved text, and local commands; a shell boundary increases the blast radius of a bad instruction.",
        "Launch a fixed executable directly, or keep the wrapper tiny, reviewed, and narrow in what arguments it accepts.",
    ),
    "dangerous-arg": Rule(
        "dangerous-arg",
        "MCP server uses a broad permission flag.",
        "Flags such as --allow-all, --privileged, --no-sandbox, and --dangerously-skip-permissions remove containment.",
        "Agents make many small tool calls. Broad permissions make an ordinary prompt failure look like intentional operator access.",
        "Grant only the paths, tools, network targets, and operations the workflow actually needs.",
    ),
    "literal-secret-env": Rule(
        "literal-secret-env",
        "Secret-like environment value is committed inline.",
        "Tokens and passwords in configs spread through repos, screenshots, issues, and copied examples.",
        "Agent projects frequently share MCP snippets. A committed sample can become the production pattern people copy.",
        "Use placeholders such as ${GITHUB_TOKEN} and load real values from the user's environment or secret store.",
    ),
    "prompt-injection-text": Rule(
        "prompt-injection-text",
        "Prompt-injection phrase appears in repository text.",
        "Hostile prompts are useful fixtures, but unlabeled ones can be mistaken for operational instructions.",
        "Agents read issues, docs, markdown, and examples as context; untrusted text can steer tool use.",
        "Keep hostile prompts in clearly labeled test fixtures or docs sections that mark them as attack examples.",
    ),
    "lethal-trifecta": Rule(
        "lethal-trifecta",
        "Data access, untrusted input, and outbound capability appear together.",
        "This combination lets an agent read sensitive data, ingest attacker-controlled instructions, and send data out.",
        "The risk is architectural, not just a bad line of code; the dangerous behavior emerges from tool composition.",
        "Split duties across profiles, remove one leg of the combination, or require human approval before outbound actions.",
    ),
}


def explain(rule_id: str) -> str | None:
    rule = RULES.get(rule_id)
    return rule.to_markdown() if rule else None

