#!/usr/bin/env node

import * as fs from 'node:fs';
import * as path from 'node:path';

import { runAuditTokens } from './commands/audit-tokens';
import { runIncident } from './commands/incident';
import { IocCommandOptions, runIoc } from './commands/ioc';
import { runMonitor } from './commands/monitor';
import { runScan } from './commands/scan';
import { runVerify } from './commands/verify';
import {
  AuditTokensCommandOptions,
  BaseCommandOptions,
  GuardrailConfig,
  IncidentCommandOptions,
  MonitorCommandOptions,
  ScanCommandOptions,
  VerifyCommandOptions,
} from './types';
import { parseJsonc } from './core/baseline';

void main();

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  try {
    switch (command) {
      case 'scan':
        process.exitCode = await runScanCommand(argv.slice(1));
        return;
      case 'monitor':
        process.exitCode = await runMonitorCommand(argv.slice(1));
        return;
      case 'audit-tokens':
        process.exitCode = await runAuditTokensCommand(argv.slice(1));
        return;
      case 'verify':
        process.exitCode = await runVerifyCommand(argv.slice(1));
        return;
      case 'incident':
        process.exitCode = await runIncidentCommand(argv.slice(1));
        return;
      case 'ioc':
        process.exitCode = await runIocCommand(argv.slice(1));
        return;
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error) {
    console.error(`GuardRail error: ${formatError(error)}`);
    process.exitCode = 1;
  }
}

async function runScanCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const options: ScanCommandOptions = {
    ...baseOptions(parsed, 0),
    threshold: parsed.flags.threshold ? Number.parseInt(parsed.flags.threshold, 10) : undefined,
    failFast: hasFlag(parsed.flags, 'fail-fast'),
    updateBaseline: hasFlag(parsed.flags, 'update-baseline'),
    generateWorkflow: hasFlag(parsed.flags, 'generate-workflow'),
    installPreCommit: hasFlag(parsed.flags, 'install-pre-commit'),
    sarif: parsed.flags.sarif,
  };
  const config = loadConfig(options.rootDir, options.configPath);
  return runScan(options, config);
}

async function runMonitorCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const options: MonitorCommandOptions = {
    ...baseOptions(parsed, 0),
    intervalMs: parsed.flags['interval-ms'] ? Number.parseInt(parsed.flags['interval-ms'], 10) : undefined,
    slackWebhook: parsed.flags['slack-webhook'],
    webhook: parsed.flags.webhook,
    once: hasFlag(parsed.flags, 'once'),
  };
  const config = loadConfig(options.rootDir, options.configPath);
  return runMonitor(options, config);
}

async function runAuditTokensCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const options: AuditTokensCommandOptions = {
    ...baseOptions(parsed, 0),
    revokeStale: hasFlag(parsed.flags, 'revoke-stale'),
    staleAfterDays: parsed.flags['stale-after-days']
      ? Number.parseInt(parsed.flags['stale-after-days'], 10)
      : undefined,
  };
  const config = loadConfig(options.rootDir, options.configPath);
  return runAuditTokens(options, config);
}

async function runVerifyCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const packageSpec = parsed.positionals[0];
  if (!packageSpec) {
    throw new Error('verify requires a package spec, for example: guardrail verify axios@1.14.0');
  }
  const options: VerifyCommandOptions = {
    ...baseOptions(parsed, 1),
    packageSpec,
    failFast: hasFlag(parsed.flags, 'fail-fast'),
  };
  const config = loadConfig(options.rootDir, options.configPath);
  return runVerify(options, config);
}

async function runIncidentCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const packageSpec = parsed.positionals[0];
  if (!packageSpec) {
    throw new Error('incident requires a package spec, for example: guardrail incident axios@1.14.1 --from 2026-03-31T00:00:00Z --to 2026-03-31T04:00:00Z');
  }
  if (!parsed.flags.from || !parsed.flags.to) {
    throw new Error('incident requires --from and --to ISO timestamps');
  }

  const options: IncidentCommandOptions = {
    ...baseOptions(parsed, 1),
    packageSpec,
    from: parsed.flags.from,
    to: parsed.flags.to,
    githubOwner: parsed.flags['github-owner'],
    githubRepo: parsed.flags['github-repo'],
    githubToken: parsed.flags['github-token'],
  };
  const config = loadConfig(options.rootDir, options.configPath);
  return runIncident(options, config);
}

async function runIocCommand(argv: string[]): Promise<number> {
  const parsed = parseArguments(argv);
  const subcommand = parsed.positionals[0] as IocCommandOptions['subcommand'] | undefined;
  if (!subcommand || !['list', 'add', 'remove', 'check'].includes(subcommand)) {
    console.log('Usage:');
    console.log('  guardrail ioc list');
    console.log('  guardrail ioc add <package-name> --reason "..." [--advisory "GHSA-..."]');
    console.log('  guardrail ioc remove <package-name>');
    console.log('  guardrail ioc check <package-name>');
    return subcommand ? 1 : 0;
  }
  const rootDir = path.resolve(parsed.flags['root-dir'] ?? process.cwd());
  const options: IocCommandOptions = {
    subcommand,
    rootDir,
    configPath: parsed.flags.config,
    packageName: parsed.positionals[1],
    reason: parsed.flags.reason,
    advisory: parsed.flags.advisory,
  };
  const config = loadConfig(rootDir, options.configPath);
  return runIoc(options, config);
}

function baseOptions(parsed: ParsedArgs, rootPositionalIndex: number): BaseCommandOptions {
  return {
    rootDir: path.resolve(parsed.flags['root-dir'] ?? parsed.positionals[rootPositionalIndex] ?? process.cwd()),
    configPath: parsed.flags.config,
    output: parsed.flags.output,
    json: hasFlag(parsed.flags, 'json'),
    quiet: hasFlag(parsed.flags, 'quiet'),
  };
}

function loadConfig(rootDir: string, configPath?: string): GuardrailConfig {
  const resolvedConfigPath = configPath
    ? path.resolve(rootDir, configPath)
    : path.join(rootDir, 'guardrail.config.json');

  if (!fs.existsSync(resolvedConfigPath)) {
    return {};
  }

  return parseJsonc<GuardrailConfig>(fs.readFileSync(resolvedConfigPath, 'utf8'));
}

interface ParsedArgs {
  flags: Record<string, string>;
  positionals: string[];
}

function parseArguments(argv: string[]): ParsedArgs {
  const flags: Record<string, string> = {};
  const positionals: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index] ?? '';
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }

    const [rawKey, inlineValue] = token.slice(2).split('=', 2);
    const key = (rawKey ?? '').trim();
    if (!key) {
      continue;
    }

    if (typeof inlineValue === 'string') {
      flags[key] = inlineValue;
      continue;
    }

    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      flags[key] = next;
      index += 1;
    } else {
      flags[key] = 'true';
    }
  }

  return { flags, positionals };
}

function hasFlag(flags: Record<string, string>, name: string): boolean {
  return flags[name] === 'true';
}

function printHelp(): void {
  console.log(`GuardRail\n`);
  console.log(`Usage:`);
  console.log(`  guardrail scan [--root-dir PATH] [--fail-fast] [--threshold 70] [--sarif guardrail.sarif]`);
  console.log(`  guardrail monitor [--root-dir PATH] [--interval-ms 25000] [--slack-webhook URL] [--webhook URL]`);
  console.log(`  guardrail audit-tokens [--root-dir PATH] [--revoke-stale] [--stale-after-days 30]`);
  console.log(`  guardrail verify <package[@version]> [--root-dir PATH] [--fail-fast]`);
  console.log(`  guardrail incident <package[@version]> --from ISO --to ISO [--github-owner OWNER --github-repo REPO --github-token TOKEN]`);
  console.log('  guardrail ioc list|add|remove|check [package-name] [--reason "..."] [--advisory "GHSA-..."]');
  console.log('');
  console.log(`Common flags:`);
  console.log(`  --config guardrail.config.json`);
  console.log(`  --output report.json`);
  console.log(`  --json`);
  console.log(`  --quiet`);
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
