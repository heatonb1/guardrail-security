import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { GuardrailConfig, IncidentCommandOptions, IncidentReport, ScanIssue } from '../types';
import { severityToNumber } from '../core/baseline';
import {
  collectWorkflowSecretReferences,
  scanWorkflowRunsForPackage,
} from '../integrations/github-actions';
import { parsePackageSpec } from '../utils/registry';

export async function runIncident(
  options: IncidentCommandOptions,
  config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const parsed = parsePackageSpec(options.packageSpec);
  const githubToken =
    options.githubToken ??
    config.github?.token ??
    (config.github?.tokenEnvVar ? process.env[config.github.tokenEnvVar] : process.env.GITHUB_TOKEN);
  const githubOwner = options.githubOwner ?? config.github?.owner;
  const githubRepo = options.githubRepo ?? config.github?.repo;

  const possibleLocalMatches = findLocalMatches(rootDir, parsed.name, parsed.version);
  const secretsAtRisk = collectPotentialSecrets(rootDir);
  let workflowRuns = [] as IncidentReport['workflowRuns'];

  if (githubOwner && githubRepo && githubToken) {
    workflowRuns = await scanWorkflowRunsForPackage(
      githubOwner,
      githubRepo,
      options.from,
      options.to,
      githubToken,
      buildIndicators(parsed.name, parsed.version),
    );
  }

  const issues = buildIssues(parsed.name, parsed.version, possibleLocalMatches, workflowRuns);
  const report: IncidentReport = {
    packageName: parsed.name,
    version: parsed.version,
    from: options.from,
    to: options.to,
    summary: buildSummary(parsed.name, parsed.version, possibleLocalMatches, workflowRuns, secretsAtRisk),
    checklist: buildChecklist(parsed.name, parsed.version),
    possibleLocalMatches,
    workflowRuns,
    secretsAtRisk,
    rotationCommands: buildRotationCommands(secretsAtRisk),
    issues,
  };

  if (options.output) {
    fs.writeFileSync(path.resolve(rootDir, options.output), `${JSON.stringify(report, null, 2)}\n`);
  }

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report, Boolean(githubOwner && githubRepo && githubToken));
  }

  return issues.some((issue) => severityToNumber(issue.severity) >= severityToNumber('high')) ? 1 : 0;
}

function buildIndicators(packageName: string, version?: string): string[] {
  return [
    packageName,
    version ? `${packageName}@${version}` : '',
    version ?? '',
    'npm install',
    'npm ci',
    'pnpm install',
    'yarn install',
    'bun install',
  ].filter(Boolean);
}

function findLocalMatches(rootDir: string, packageName: string, version?: string): string[] {
  const matches = new Set<string>();
  const candidateFiles = [
    'package.json',
    'package-lock.json',
    'pnpm-lock.yaml',
    'yarn.lock',
    'bun.lock',
    '.npmrc',
  ].map((file) => path.join(rootDir, file));

  for (const filePath of candidateFiles) {
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      continue;
    }
    const text = fs.readFileSync(filePath, 'utf8');
    if (!text.includes(packageName)) {
      continue;
    }
    if (version && !text.includes(version)) {
      continue;
    }
    matches.add(path.relative(rootDir, filePath));
  }

  const directInstallPath = path.join(rootDir, 'node_modules', packageName, 'package.json');
  if (fs.existsSync(directInstallPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(directInstallPath, 'utf8')) as Record<string, unknown>;
      if (!version || parsed.version === version) {
        matches.add(path.relative(rootDir, directInstallPath));
      }
    } catch {
      // ignore malformed package
    }
  }

  return Array.from(matches).sort();
}

function collectPotentialSecrets(rootDir: string): string[] {
  const secrets = new Set<string>();

  for (const secret of collectWorkflowSecretReferences(rootDir)) {
    secrets.add(secret);
  }

  for (const envName of Object.keys(process.env as Record<string, string | undefined>)) {
    if (/(SECRET|TOKEN|PASSWORD|KEY|AWS_|AZURE_|GCP|GOOGLE_|SSH|NPM|GITHUB)/i.test(envName)) {
      secrets.add(envName);
    }
  }

  for (const envFile of fs.readdirSync(rootDir).filter((entry: string) => /^\.env(?:\..+)?$/.test(entry))) {
    const filePath = path.join(rootDir, envFile);
    const text = fs.readFileSync(filePath, 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z0-9_\-.]+)\s*=/);
      if (match?.[1]) {
        secrets.add(match[1]);
      }
    }
  }

  const home = os.homedir();
  if (fs.existsSync(path.join(home, '.aws', 'credentials'))) {
    secrets.add('AWS_ACCESS_KEY_ID');
    secrets.add('AWS_SECRET_ACCESS_KEY');
  }
  if (fs.existsSync(path.join(home, '.npmrc'))) {
    secrets.add('NPM_TOKEN');
  }
  if (fs.existsSync(path.join(home, '.docker', 'config.json'))) {
    secrets.add('DOCKER_AUTH_CONFIG');
  }
  if (fs.existsSync(path.join(home, '.config', 'gcloud', 'application_default_credentials.json'))) {
    secrets.add('GOOGLE_APPLICATION_CREDENTIALS');
  }
  if (fs.existsSync(path.join(home, '.azure'))) {
    secrets.add('AZURE_CLIENT_SECRET');
    secrets.add('AZURE_ACCESS_TOKEN');
  }
  if (fs.existsSync(path.join(home, '.kube', 'config'))) {
    secrets.add('KUBECONFIG');
  }
  if (fs.existsSync(path.join(home, '.ssh'))) {
    const sshFiles = fs.readdirSync(path.join(home, '.ssh')).filter((entry: string) => /^id_[a-z0-9_]+$/i.test(entry));
    if (sshFiles.length > 0) {
      secrets.add('SSH_PRIVATE_KEY');
    }
  }

  return Array.from(secrets).sort();
}

function buildRotationCommands(secretsAtRisk: string[]): Record<string, string[]> {
  const commands: Record<string, string[]> = {
    npm: [
      'npm token list',
      'npm token revoke <TOKEN_ID>',
      'npm profile enable-2fa auth-and-writes',
    ],
    github: [
      'gh secret list',
      'gh secret set <SECRET_NAME> < ./new-secret.txt',
      'gh auth token',
    ],
    aws: [
      'aws iam create-access-key --user-name <USER_NAME>',
      'aws iam update-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID> --status Inactive',
      'aws iam delete-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID>',
    ],
    gcp: [
      'gcloud iam service-accounts keys create ./new-key.json --iam-account <SERVICE_ACCOUNT_EMAIL>',
      'gcloud iam service-accounts keys delete <OLD_KEY_ID> --iam-account <SERVICE_ACCOUNT_EMAIL>',
    ],
    azure: [
      'az ad app credential reset --id <APP_ID> --append',
      'az ad app credential list --id <APP_ID>',
    ],
    docker: [
      'docker logout',
      'docker login',
    ],
  };

  if (!secretsAtRisk.some((secret) => /AWS_/i.test(secret))) {
    delete commands.aws;
  }
  if (!secretsAtRisk.some((secret) => /GOOGLE|GCP/i.test(secret))) {
    delete commands.gcp;
  }
  if (!secretsAtRisk.some((secret) => /AZURE/i.test(secret))) {
    delete commands.azure;
  }
  if (!secretsAtRisk.some((secret) => /DOCKER/i.test(secret))) {
    delete commands.docker;
  }

  return commands;
}

function buildChecklist(packageName: string, version?: string): string[] {
  return [
    `Freeze installs and deployments that could resolve ${packageName}${version ? `@${version}` : ''}.`,
    'Pin to a known-good version and re-run installs with --ignore-scripts until triage is complete.',
    'Treat any machine that executed the compromised install path as potentially fully compromised.',
    'Rotate npm tokens, cloud credentials, GitHub secrets, SSH keys, and CI/CD secrets reachable from the affected environment.',
    'Review CI/CD runs in the exposure window, especially runs that executed npm install, npm ci, pnpm install, yarn install, or bun install.',
    'Check outbound network logs for postinstall-driven C2 traffic and package manager logs for suspicious lifecycle script execution.',
    'Rebuild affected runners and developer machines from known-good images instead of attempting in-place cleanup when malware artifacts are found.',
  ];
}

function buildSummary(
  packageName: string,
  version: string | undefined,
  possibleLocalMatches: string[],
  workflowRuns: IncidentReport['workflowRuns'],
  secretsAtRisk: string[],
): string[] {
  const summary: string[] = [];
  summary.push(
    possibleLocalMatches.length > 0
      ? `${packageName}${version ? `@${version}` : ''} appears in local manifests, lockfiles, or installed packages.`
      : `No direct local reference to ${packageName}${version ? `@${version}` : ''} was found in the obvious project files.`,
  );

  const possibleRuns = workflowRuns.filter((run) => run.possibleMatch);
  if (workflowRuns.length > 0) {
    summary.push(
      possibleRuns.length > 0
        ? `${String(possibleRuns.length)} GitHub Actions run(s) in the requested window contained matching package indicators or install commands.`
        : 'GitHub Actions logs were scanned for the requested window and no matching package indicators were found.',
    );
  } else {
    summary.push('GitHub Actions logs were not scanned because repository coordinates or a GitHub token were not supplied.');
  }

  summary.push(`${String(secretsAtRisk.length)} potentially exposed secret or credential names were identified from project configuration and local environment hints.`);
  return summary;
}

function buildIssues(
  packageName: string,
  version: string | undefined,
  possibleLocalMatches: string[],
  workflowRuns: IncidentReport['workflowRuns'],
): ScanIssue[] {
  const issues: ScanIssue[] = [];

  if (possibleLocalMatches.length > 0) {
    issues.push({
      id: `${packageName}:local-match`,
      code: 'GR_INCIDENT_LOCAL_MATCH',
      category: 'incident',
      severity: 'high',
      title: 'The package appears in local project state',
      description:
        `${packageName}${version ? `@${version}` : ''} was found in project manifests, lockfiles, or installed packages. This environment should be treated as potentially exposed until install timing is confirmed.`,
      evidence: possibleLocalMatches,
      recommendation:
        'Check install timestamps, lockfile history, and runner logs. If the package was installed during the exposure window, assume compromise and rotate reachable credentials.',
    });
  }

  const matchingRuns = workflowRuns.filter((run) => run.possibleMatch);
  if (matchingRuns.length > 0) {
    issues.push({
      id: `${packageName}:workflow-runs`,
      code: 'GR_INCIDENT_CI_MATCH',
      category: 'incident',
      severity: 'critical',
      title: 'CI/CD runs may have installed the affected package',
      description:
        `${String(matchingRuns.length)} GitHub Actions run(s) in the requested window contained matching package indicators or package-manager install commands.`,
      evidence: matchingRuns.slice(0, 10).map((run) => `${run.name} (${run.createdAt}) -> ${run.matches.join('; ')}`),
      recommendation:
        'Immediately rotate all secrets injected into those runs and rebuild the affected runner environments from a clean image.',
    });
  }

  return issues;
}

function printReport(report: IncidentReport, githubScanned: boolean): void {
  console.log(`GuardRail incident report for ${report.packageName}${report.version ? `@${report.version}` : ''}`);
  console.log(`window: ${report.from} -> ${report.to}`);
  console.log('');
  console.log('Summary:');
  for (const line of report.summary) {
    console.log(`- ${line}`);
  }

  console.log('');
  console.log('Checklist:');
  for (const item of report.checklist) {
    console.log(`- ${item}`);
  }

  console.log('');
  console.log('Local matches:');
  if (report.possibleLocalMatches.length === 0) {
    console.log('- none');
  } else {
    for (const match of report.possibleLocalMatches) {
      console.log(`- ${match}`);
    }
  }

  console.log('');
  console.log(`GitHub Actions scan: ${githubScanned ? 'performed' : 'skipped'}`);
  if (report.workflowRuns.length === 0) {
    console.log('- no runs available');
  } else {
    for (const run of report.workflowRuns) {
      console.log(`- ${run.name} ${run.createdAt} ${run.possibleMatch ? '[possible match]' : ''}`);
      console.log(`  ${run.htmlUrl}`);
      if (run.matches.length > 0) {
        console.log(`  matches: ${run.matches.join(' | ')}`);
      }
    }
  }

  console.log('');
  console.log('Potential secrets at risk:');
  if (report.secretsAtRisk.length === 0) {
    console.log('- none inferred');
  } else {
    for (const secret of report.secretsAtRisk) {
      console.log(`- ${secret}`);
    }
  }

  console.log('');
  console.log('Rotation commands:');
  for (const [provider, commands] of Object.entries(report.rotationCommands)) {
    console.log(`- ${provider}`);
    for (const command of commands) {
      console.log(`  ${command}`);
    }
  }

  if (report.issues.length > 0) {
    console.log('');
    console.log('Findings:');
    for (const issue of report.issues) {
      console.log(`- [${issue.severity}] ${issue.code}: ${issue.title}`);
      console.log(`  ${issue.description}`);
      if (issue.evidence && issue.evidence.length > 0) {
        console.log(`  evidence: ${issue.evidence.join(' | ')}`);
      }
      if (issue.recommendation) {
        console.log(`  action: ${issue.recommendation}`);
      }
    }
  }
}
