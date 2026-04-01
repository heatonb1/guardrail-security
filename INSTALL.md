# GuardRail installation and rollout

This is the shortest path from download to a working first scan.

## Prerequisites

- Node.js 20 or newer
- npm 10 or newer
- internet access for `verify` and `monitor`
- a GitHub token only if you want `incident` to read GitHub Actions logs

## Path 1: developer machine

### 1. Get the code

Clone the repository or unpack the release archive.

```bash
git clone https://github.com/guardrail-security/guardrail.git
cd guardrail
```

### 2. Install dependencies

```bash
npm install
```

### 3. Build the CLI

```bash
npm run build
```

### 4. Create or review config

Copy the example file if you want a clean starting point.

```bash
cp guardrail.config.json your-project/guardrail.config.json
```

At minimum, adjust:

- `scan.trustedPackages`
- `tokenPolicy.staleAfterDays`
- `github.owner`, `github.repo`, and `github.tokenEnvVar` if you plan to use `incident`
- notification settings if you want live alerts

### 5. Run the first scan against a real Node project

```bash
cd /path/to/your-node-project
npx /path/to/guardrail/dist/src/index.js scan --fail-fast --sarif guardrail.sarif
```

If you installed GuardRail globally instead:

```bash
guardrail scan --fail-fast --sarif guardrail.sarif
```

### 6. Review the first-run baseline

The first scan writes a signed baseline under `.guardrail/` by default.

Files created there:

- `.guardrail/baseline.json`
- `.guardrail/baseline-private.pem`
- `.guardrail/baseline-public.pem`

Commit the baseline file if you want the project baseline to travel with the repository. Do **not** commit the private key unless you intentionally want a shared signing identity. In most teams, keep the private key in CI or a secure developer secret store.

### 7. Add local pre-commit protection

```bash
guardrail scan --install-pre-commit
```

That writes `.git/hooks/pre-commit` so risky dependency changes fail before commit.

## Path 2: use GuardRail without global install

From any Node project:

```bash
npx guardrail-security scan
npx guardrail-security audit-tokens
npx guardrail-security verify axios@1.14.0
```

## Path 3: GitHub Actions rollout

### 1. Add the workflow file

Copy `.github/workflows/guardrail.yml` into the target repository.

Or generate it from GuardRail itself:

```bash
guardrail scan --generate-workflow
```

### 2. Make sure the workflow can upload SARIF

The generated workflow already includes these permissions:

- `contents: read`
- `actions: read`
- `security-events: write`
- `id-token: write`

### 3. Keep dependency installation script-safe in CI

The workflow intentionally installs project dependencies with:

```bash
npm ci --ignore-scripts
```

That lets GuardRail inspect lifecycle hooks before the hooks execute.

### 4. Decide whether GuardRail should fail the build

Default fail-fast usage:

```bash
guardrail scan --fail-fast --sarif guardrail.sarif
```

Tune the policy in `guardrail.config.json`:

```jsonc
{
  "scan": {
    "riskThreshold": 70,
    "failOnSeverity": "high"
  }
}
```

### 5. Add GitHub token support for incident response

If you want `guardrail incident` to inspect workflow logs, add a token with Actions read access.

Example repository secret setup:

```bash
gh secret set GITHUB_TOKEN < ./github-token.txt
```

Then set in config:

```jsonc
{
  "github": {
    "owner": "your-org",
    "repo": "your-repo",
    "tokenEnvVar": "GITHUB_TOKEN"
  }
}
```

## Optional: live monitoring

### Slack webhook

```jsonc
{
  "monitor": {
    "packages": ["axios", "react"],
    "slackWebhook": "https://hooks.slack.com/services/..."
  }
}
```

Run:

```bash
guardrail monitor
```

### Generic webhook

```jsonc
{
  "monitor": {
    "packages": ["axios"],
    "webhook": "https://your-webhook.example/guardrail"
  }
}
```

### Email via SMTP

```jsonc
{
  "monitor": {
    "packages": ["axios"],
    "email": {
      "host": "smtp.example.com",
      "port": 587,
      "secure": false,
      "username": "smtp-user",
      "password": "smtp-password",
      "from": "guardrail@example.com",
      "to": ["secops@example.com"]
    }
  }
}
```

## Recommended rollout order

1. run `guardrail scan` on a clean branch
2. review and commit the baseline policy files
3. add `guardrail audit-tokens` to maintainer and CI environments
4. enable the GitHub Actions workflow
5. turn on `--fail-fast`
6. enable live monitoring for the packages you trust most
7. use `guardrail incident` for every supply chain advisory that overlaps your dependency tree

## Five-minute first scan

Assuming GuardRail is already downloaded:

```bash
cd /path/to/guardrail
npm install
npm run build
cd /path/to/your-node-project
cp /path/to/guardrail/guardrail.config.json .
node /path/to/guardrail/dist/src/index.js scan --fail-fast --sarif guardrail.sarif
```

That gets you:

- a signed baseline
- dependency mutation analysis
- ghost dependency checks
- lifecycle script inventory and scoring
- a SARIF file for GitHub code scanning

## Troubleshooting

### No lockfile found

GuardRail can still scan installed packages from `node_modules`, but it gets stronger when a lockfile exists.

### `verify` says `fetch failed`

The command needs network access to the npm registry and usually the source host.

### GitHub log scan says skipped

Set `github.owner`, `github.repo`, and a token through `github.tokenEnvVar` or `--github-token`.

### SMTP alerts fail

Check host, port, auth mode, firewall, and whether the SMTP server accepts `AUTH PLAIN`.

### False positives on generated build artifacts

This usually affects `verify`, not `scan`. Generated tarball files that are intentionally not committed to source will produce `partial` instead of `verified`.
