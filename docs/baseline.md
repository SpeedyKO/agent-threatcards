# Baseline Workflow

Baselines let teams adopt `agent-threatcards` without stopping every build on existing findings.

Create a baseline from the current repo:

```bash
agent-threatcards . --write-baseline agent-threatcards.baseline.json
```

Or initialize both the baseline and GitHub Code Scanning workflow:

```bash
agent-threatcards init
```

Then scan with the baseline:

```bash
agent-threatcards . --baseline agent-threatcards.baseline.json
```

Only findings whose stable fingerprint is not in the baseline remain in the report and affect the exit code.

## Recommended CI Pattern

1. Generate and commit a baseline during adoption.
2. Run `agent-threatcards . --baseline agent-threatcards.baseline.json` in CI.
3. Remove baseline entries as risks are fixed.
4. Regenerate the baseline only after review.

## Fingerprints

Fingerprints are based on rule id, repository-relative path, and evidence. They are stable across line movement but change when the actual risk changes.
