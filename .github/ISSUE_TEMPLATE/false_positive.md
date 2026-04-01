---
name: False Positive Report
about: Report a package incorrectly flagged by GuardRail
labels: false-positive
---

## Package Information

- Package name:
- Package version:
- GuardRail finding code (e.g., GR_GHOST_DEPENDENCY_UNIMPORTED):

## Why This Is a False Positive

Explain why this detection is incorrect. For example: "This is a native addon that requires node-gyp at install time but is imported via a conditional require that GuardRail's static analysis does not detect."

## Your Configuration

Paste relevant sections of your `guardrail.config.json` (redact sensitive values):

```json

```

## GuardRail Version

Output of `guardrail --help` or `npm ls guardrail-security`:
