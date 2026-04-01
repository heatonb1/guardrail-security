# Contributing to GuardRail

## Development Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Build: `npm run build`
4. Run a test scan: `node dist/src/index.js scan`

## Submitting a New Built-in IOC

To add a known malicious package to the built-in IOC database:

1. Open an issue using the "New IOC" template
2. Provide:
   - Package name (exact npm registry name)
   - Advisory link (GHSA, CVE, or detailed write-up)
   - Affected versions
   - Discovery date
   - Brief description of the malicious behavior
3. Submit a PR adding the entry to the `BUILTIN_IOCS` array in `src/commands/ioc.ts` and the `builtinIocs` object in `src/commands/scan.ts`

Evidence requirements: at minimum, a published advisory (GHSA or CVE) or a reproducible technical analysis showing malicious behavior.

## Reporting a False Positive

Open an issue using the "False Positive" template. Include:
- Package name and version that was flagged
- The GuardRail finding code (e.g., GR_GHOST_DEPENDENCY_UNIMPORTED)
- Why this is a false positive (e.g., the package is a native addon that legitimately needs install scripts)
- Your guardrail.config.json (redact sensitive values)

## Adding a New Script Risk Pattern

1. Identify the behavioral pattern (e.g., a new obfuscation technique)
2. Add a new rule to the `RULES` array in `src/core/script-analyzer.ts`
3. If the pattern is part of a dangerous combination, add a compound bonus in `calculateCompoundBonus()`
4. Test against known-good and known-malicious packages to verify detection and false positive rates
5. Submit a PR with your test cases

## Code Style

- TypeScript strict mode is enabled (`strict: true` in tsconfig.json)
- Avoid `any` unless there is a documented reason
- Zero external runtime dependencies is a project goal -- all functionality uses Node.js built-in APIs
- Run `npm run build` before submitting -- the build must pass with zero errors

## Pull Request Checklist

- [ ] `npm run build` passes with zero errors
- [ ] New detection rules include test rationale in the PR description
- [ ] README.md is updated if commands or flags changed
- [ ] No `console.log` debug statements left in code
