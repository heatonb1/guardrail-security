import * as childProcess from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { GuardrailConfig, ScanIssue, TokenAuditResult, TokenDiscovery } from '../types';
import { redactSecret } from './baseline';

const WORKFLOW_EXTENSIONS = ['.yml', '.yaml'];

export async function scanTokenExposure(
  rootDir: string,
  config: GuardrailConfig,
): Promise<TokenAuditResult> {
  const findings: TokenDiscovery[] = [];
  const issues: ScanIssue[] = [];

  const npmrcFiles = discoverNpmrcFiles(rootDir);
  for (const filePath of npmrcFiles) {
    findings.push(...readTokensFromNpmrc(filePath));
  }

  findings.push(...readTokensFromEnvironment());

  const workflowSignals = inspectCiWorkflows(rootDir);
  findings.push(...workflowSignals.tokenReferences);

  const cliTokens = readTokensFromNpmCli(rootDir);
  findings.push(...cliTokens);

  const staticPublishTokensFound = findings.some(
    (finding) => finding.tokenKind === 'traditional-static' && finding.canPublish !== false,
  );

  const oidcTrustedPublishingDetected = workflowSignals.oidcTrustedPublishingDetected;
  const selfHostedRunnerDetected = workflowSignals.selfHostedRunnerDetected;
  const mixedModeRisk =
    oidcTrustedPublishingDetected &&
    findings.some((finding) =>
      finding.tokenKind === 'traditional-static'
        ? finding.canPublish !== false
        : finding.tokenKind === 'granular-access-token' && finding.canPublish !== false,
    );

  if (staticPublishTokensFound) {
    issues.push({
      id: 'token:static-publish-token',
      code: 'GR_STATIC_TOKEN',
      category: 'token-exposure',
      severity: 'high',
      title: 'Static npm publish tokens were discovered locally',
      description:
        'GuardRail found one or more static npm tokens in .npmrc files, environment variables, or CI configuration. Static tokens create a parallel publish path outside trusted publishing.',
      recommendation:
        'Move package publishing to OIDC trusted publishing, revoke long-lived write tokens, and keep only narrowly scoped read tokens where unavoidable.',
      evidence: findings
        .filter((finding) => finding.tokenKind === 'traditional-static')
        .map((finding) => `${finding.sourceType}:${finding.sourcePath ?? finding.envVar ?? 'unknown'}`),
    });
  }

  if (mixedModeRisk && !config.tokenPolicy?.mixedModeAllowed) {
    issues.push({
      id: 'token:mixed-mode',
      code: 'GR_MIXED_MODE_PUBLISHING',
      category: 'token-exposure',
      severity: 'critical',
      title: 'Trusted publishing and static publish tokens coexist',
      description:
        'The project appears to be configured for OIDC trusted publishing while traditional token-based publish credentials are still present. This recreates the exact blind spot exploited in recent npm supply chain compromises.',
      recommendation:
        'Enable “Require two-factor authentication and disallow tokens” for the package, revoke legacy write tokens, and keep only short-lived read credentials for installs if necessary.',
    });
  }

  if (selfHostedRunnerDetected && oidcTrustedPublishingDetected) {
    issues.push({
      id: 'token:self-hosted-runner',
      code: 'GR_SELF_HOSTED_RUNNER',
      category: 'configuration',
      severity: 'medium',
      title: 'Self-hosted CI runners detected alongside npm trusted publishing intent',
      description:
        'npm trusted publishing currently depends on provider-managed runners. Self-hosted runners frequently lead teams back to manual token-based publishing fallbacks.',
      recommendation:
        'Prefer provider-hosted publish jobs for npm trusted publishing. If self-hosted jobs are required for build steps, split build and publish into separate stages and publish from a supported hosted runner.',
    });
  }

  for (const finding of findings) {
    if (finding.tokenKind === 'granular-access-token' && finding.canPublish !== false && !finding.expiresAt) {
      issues.push({
        id: `token:${finding.id ?? finding.tokenPreview}`,
        code: 'GR_TOKEN_NO_EXPIRY',
        category: 'token-exposure',
        severity: 'medium',
        title: 'A write-capable granular token has no visible expiry metadata',
        description:
          'Write-capable granular tokens should be short-lived. Missing expiry metadata is a policy gap even when the token is scoped.',
        recommendation:
          'Create short-lived replacement tokens and revoke this token once the new path is validated.',
        evidence: [finding.sourcePath ?? finding.envVar ?? 'npm token list'],
      });
    }
  }

  const staleAfterDays = config.tokenPolicy?.staleAfterDays ?? 30;
  const suggestedRevocations = findings
    .filter((finding) => shouldSuggestRevocation(finding, staleAfterDays))
    .map((finding) => (finding.id ? `npm token revoke ${finding.id}` : 'npm token list && npm token revoke <TOKEN_ID>'));

  return {
    rootDir,
    oidcTrustedPublishingDetected,
    selfHostedRunnerDetected,
    staticPublishTokensFound,
    mixedModeRisk,
    findings: dedupeFindings(findings),
    issues,
    suggestedRevocations: Array.from(new Set(suggestedRevocations)),
  };
}

export function revokeSuggestedTokens(findings: TokenDiscovery[], staleAfterDays: number): string[] {
  const executed: string[] = [];
  for (const finding of findings) {
    if (!shouldSuggestRevocation(finding, staleAfterDays) || !finding.id) {
      continue;
    }
    const result = childProcess.spawnSync('npm', ['token', 'revoke', finding.id], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    if (result.status === 0) {
      executed.push(finding.id);
    }
  }
  return executed;
}

function discoverNpmrcFiles(rootDir: string): string[] {
  const candidates = new Set<string>();
  candidates.add(path.join(rootDir, '.npmrc'));
  candidates.add(path.join(os.homedir(), '.npmrc'));
  candidates.add(path.join(os.homedir(), '.config', 'npm', 'npmrc'));
  if (process.env.NPM_CONFIG_USERCONFIG) {
    candidates.add(path.resolve(process.env.NPM_CONFIG_USERCONFIG));
  }
  return Array.from(candidates).filter((candidate) => fs.existsSync(candidate));
}

function readTokensFromNpmrc(filePath: string): TokenDiscovery[] {
  const text = fs.readFileSync(filePath, 'utf8');
  const findings: TokenDiscovery[] = [];

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }

    const tokenMatch = line.match(/^(?<key>(?:\/\/[^\s=]+:)?_authToken)\s*=\s*(?<value>.+)$/);
    if (tokenMatch?.groups?.value) {
      const value = tokenMatch.groups.value.trim();
      const envReferenceMatch = value.match(/^\$\{([^}]+)\}$/);
      findings.push({
        sourceType: 'npmrc',
        sourcePath: filePath,
        envVar: envReferenceMatch?.[1],
        tokenPreview: redactSecret(value),
        tokenKind: 'traditional-static',
        canPublish: true,
        note: envReferenceMatch?.[1]
          ? `token is sourced from environment variable ${envReferenceMatch[1]}`
          : undefined,
      });
      continue;
    }

    if (/^_auth\s*=/.test(line)) {
      findings.push({
        sourceType: 'npmrc',
        sourcePath: filePath,
        tokenPreview: '_auth=<redacted>',
        tokenKind: 'traditional-static',
        canPublish: true,
        note: 'base64 _auth credentials were present in .npmrc',
      });
    }
  }

  return findings;
}

function readTokensFromEnvironment(): TokenDiscovery[] {
  const findings: TokenDiscovery[] = [];
  const explicitNames = new Set([
    'NPM_TOKEN',
    'NODE_AUTH_TOKEN',
    'NPM_AUTH_TOKEN',
    'NPM_CONFIG__AUTH',
    'NPM_CONFIG__AUTHTOKEN',
    'NPM_PUBLISH_TOKEN',
  ]);

  for (const [name, value] of Object.entries(process.env as Record<string, string | undefined>)) {
    if (!value) {
      continue;
    }

    const interesting = explicitNames.has(name) || (/NPM/i.test(name) && /(TOKEN|AUTH)/i.test(name));
    if (!interesting) {
      continue;
    }

    findings.push({
      sourceType: 'env',
      envVar: name,
      tokenPreview: redactSecret(value),
      tokenKind: 'traditional-static',
      canPublish: true,
    });
  }

  return findings;
}

function inspectCiWorkflows(rootDir: string): {
  oidcTrustedPublishingDetected: boolean;
  selfHostedRunnerDetected: boolean;
  tokenReferences: TokenDiscovery[];
} {
  const tokenReferences: TokenDiscovery[] = [];
  let oidcTrustedPublishingDetected = false;
  let selfHostedRunnerDetected = false;

  const workflowFiles = collectWorkflowFiles(rootDir);
  for (const filePath of workflowFiles) {
    const text = fs.readFileSync(filePath, 'utf8');

    if (/id-token\s*:\s*write/i.test(text) && /npm\s+publish/i.test(text)) {
      oidcTrustedPublishingDetected = true;
    }
    if (/trusted publishing/i.test(text)) {
      oidcTrustedPublishingDetected = true;
    }
    if (/runs-on\s*:\s*\[?[^\n]*self-hosted/i.test(text) || /runs-on\s*:\s*self-hosted/i.test(text)) {
      selfHostedRunnerDetected = true;
    }
    if (/id_tokens:/i.test(text) && /npm:registry\.npmjs\.org/i.test(text)) {
      oidcTrustedPublishingDetected = true;
    }

    const envReferences = text.match(/\$\{\{\s*secrets\.([A-Za-z0-9_\-]+)\s*\}\}/g) ?? [];
    for (const reference of envReferences) {
      const match = reference.match(/secrets\.([A-Za-z0-9_\-]+)/);
      if (!match?.[1] || !/npm|token|auth/i.test(match[1])) {
        continue;
      }
      tokenReferences.push({
        sourceType: 'workflow',
        sourcePath: filePath,
        envVar: match[1],
        tokenPreview: '${{ secrets.REDACTED }}',
        tokenKind: 'traditional-static',
        canPublish: true,
      });
    }
  }

  return {
    oidcTrustedPublishingDetected,
    selfHostedRunnerDetected,
    tokenReferences,
  };
}

function collectWorkflowFiles(rootDir: string): string[] {
  const workflowFiles: string[] = [];
  const workflowDir = path.join(rootDir, '.github', 'workflows');
  if (fs.existsSync(workflowDir)) {
    for (const entry of fs.readdirSync(workflowDir)) {
      const fullPath = path.join(workflowDir, entry);
      if (WORKFLOW_EXTENSIONS.includes(path.extname(entry).toLowerCase()) && fs.statSync(fullPath).isFile()) {
        workflowFiles.push(fullPath);
      }
    }
  }

  const gitlab = path.join(rootDir, '.gitlab-ci.yml');
  if (fs.existsSync(gitlab)) {
    workflowFiles.push(gitlab);
  }

  const circleci = path.join(rootDir, '.circleci', 'config.yml');
  if (fs.existsSync(circleci)) {
    workflowFiles.push(circleci);
  }

  return workflowFiles;
}

function readTokensFromNpmCli(rootDir: string): TokenDiscovery[] {
  try {
    const result = childProcess.spawnSync('npm', ['token', 'list', '--json'], {
      cwd: rootDir,
      encoding: 'utf8',
      maxBuffer: 5 * 1024 * 1024,
    });
    if (result.status !== 0 || !result.stdout) {
      return [];
    }

    const parsed = JSON.parse(result.stdout) as Array<Record<string, unknown>>;
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.map(normalizeCliTokenRecord).filter((record): record is TokenDiscovery => Boolean(record));
  } catch {
    return [];
  }
}

function normalizeCliTokenRecord(record: Record<string, unknown>): TokenDiscovery | null {
  const id =
    typeof record.id === 'string'
      ? record.id
      : typeof record.key === 'string'
        ? record.key
        : typeof record.token === 'string'
          ? record.token
          : undefined;

  const expiresAt =
    typeof record.expires === 'string'
      ? record.expires
      : typeof record.expiresAt === 'string'
        ? record.expiresAt
        : undefined;

  const createdAt = typeof record.created === 'string' ? record.created : undefined;
  const lastUsedAt = typeof record.lastUsed === 'string' ? record.lastUsed : undefined;
  const readonly = Boolean(record.readonly);
  const automation = Boolean(record.automation);
  const bypass2FA = automation || Boolean(record.bypass2fa) || Boolean(record.bypass2FA);

  return {
    sourceType: 'npm-cli',
    tokenPreview: redactSecret(id ?? 'token'),
    tokenKind: 'granular-access-token',
    canPublish: !readonly,
    bypass2FA,
    createdAt,
    lastUsedAt,
    expiresAt,
    id,
  };
}

function shouldSuggestRevocation(finding: TokenDiscovery, staleAfterDays: number): boolean {
  if (finding.tokenKind === 'traditional-static') {
    return true;
  }
  if (finding.canPublish === false) {
    return false;
  }
  if (!finding.expiresAt) {
    return true;
  }
  const expiry = Date.parse(finding.expiresAt);
  if (!Number.isFinite(expiry)) {
    return true;
  }
  const maxFuture = Date.now() + staleAfterDays * 24 * 60 * 60 * 1000;
  return expiry > maxFuture;
}

function dedupeFindings(findings: TokenDiscovery[]): TokenDiscovery[] {
  const seen = new Map<string, TokenDiscovery>();
  for (const finding of findings) {
    const key = [
      finding.sourceType,
      finding.sourcePath ?? '',
      finding.envVar ?? '',
      finding.id ?? '',
      finding.tokenPreview,
    ].join('|');
    if (!seen.has(key)) {
      seen.set(key, finding);
    }
  }
  return Array.from(seen.values());
}
