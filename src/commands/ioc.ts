import * as fs from 'node:fs';
import * as path from 'node:path';

import { CustomIoc, GuardrailConfig } from '../types';
import { parseJsonc } from '../core/baseline';

const BUILTIN_IOCS: ReadonlyArray<{ packageName: string; reason: string; advisory: string }> = [
  {
    packageName: 'plain-crypto-js',
    reason: 'Package used in the March 2026 axios supply chain attack as a RAT dropper (SILKBELL)',
    advisory: 'GHSA-fw8c-xr5c-95f9',
  },
];

export interface IocCommandOptions {
  subcommand: 'list' | 'add' | 'remove' | 'check';
  rootDir: string;
  configPath?: string;
  packageName?: string;
  reason?: string;
  advisory?: string;
}

export async function runIoc(options: IocCommandOptions, config: GuardrailConfig): Promise<number> {
  switch (options.subcommand) {
    case 'list':
      return listIocs(config);
    case 'add':
      return addIoc(options);
    case 'remove':
      return removeIoc(options);
    case 'check':
      return checkIoc(options, config);
    default:
      console.error(`Unknown ioc subcommand: ${options.subcommand}`);
      return 1;
  }
}

function listIocs(config: GuardrailConfig): number {
  console.log('GuardRail IOC Database\n');

  console.log('Built-in IOCs:');
  if (BUILTIN_IOCS.length === 0) {
    console.log('  (none)');
  }
  for (const ioc of BUILTIN_IOCS) {
    console.log(`  ${ioc.packageName}`);
    console.log(`    reason: ${ioc.reason}`);
    console.log(`    advisory: ${ioc.advisory}`);
    console.log(`    source: built-in`);
  }

  console.log('');
  console.log('Custom IOCs:');
  const custom = config.customIocs ?? [];
  if (custom.length === 0) {
    console.log('  (none)');
  }
  for (const ioc of custom) {
    console.log(`  ${ioc.packageName}`);
    console.log(`    reason: ${ioc.reason}`);
    if (ioc.advisory) console.log(`    advisory: ${ioc.advisory}`);
    if (ioc.addedBy) console.log(`    added by: ${ioc.addedBy}`);
    if (ioc.addedAt) console.log(`    added at: ${ioc.addedAt}`);
    console.log(`    source: custom`);
  }

  const total = BUILTIN_IOCS.length + custom.length;
  console.log(`\nTotal: ${String(total)} IOC entries (${String(BUILTIN_IOCS.length)} built-in, ${String(custom.length)} custom)`);
  return 0;
}

function addIoc(options: IocCommandOptions): number {
  if (!options.packageName) {
    console.error('ioc add requires a package name');
    return 1;
  }
  if (!options.reason) {
    console.error('ioc add requires --reason "..."');
    return 1;
  }
  if (!isValidPackageName(options.packageName)) {
    console.error(`Invalid npm package name: ${options.packageName}`);
    return 1;
  }

  const configPath = resolveConfigPath(options.rootDir, options.configPath);
  const config = loadConfigFile(configPath);

  if (!config.customIocs) {
    config.customIocs = [];
  }

  const existing = (config.customIocs as CustomIoc[]).find((ioc: CustomIoc) => ioc.packageName === options.packageName);
  if (existing) {
    console.error(`IOC entry for ${options.packageName} already exists. Remove it first to update.`);
    return 1;
  }

  const entry: CustomIoc = {
    packageName: options.packageName,
    reason: options.reason,
    advisory: options.advisory,
    addedBy: process.env.USER ?? 'unknown',
    addedAt: new Date().toISOString().slice(0, 10),
  };

  (config.customIocs as CustomIoc[]).push(entry);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  console.log(`Added IOC entry for ${entry.packageName}`);
  console.log(`  reason: ${entry.reason}`);
  if (entry.advisory) console.log(`  advisory: ${entry.advisory}`);
  console.log(`  added by: ${entry.addedBy}`);
  console.log(`  added at: ${entry.addedAt}`);
  console.log(`  config: ${configPath}`);
  return 0;
}

function removeIoc(options: IocCommandOptions): number {
  if (!options.packageName) {
    console.error('ioc remove requires a package name');
    return 1;
  }

  const isBuiltin = BUILTIN_IOCS.some((ioc) => ioc.packageName === options.packageName);
  if (isBuiltin) {
    console.error(`Cannot remove built-in IOC: ${options.packageName}. Built-in IOCs are hardcoded and cannot be removed.`);
    return 1;
  }

  const configPath = resolveConfigPath(options.rootDir, options.configPath);
  const config = loadConfigFile(configPath);

  const customIocs = (config.customIocs ?? []) as CustomIoc[];
  const index = customIocs.findIndex((ioc: CustomIoc) => ioc.packageName === options.packageName);
  if (index === -1) {
    console.error(`No custom IOC entry found for: ${options.packageName}`);
    return 1;
  }

  customIocs.splice(index, 1);
  config.customIocs = customIocs;
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  console.log(`Removed custom IOC entry for ${options.packageName}`);
  return 0;
}

function checkIoc(options: IocCommandOptions, config: GuardrailConfig): number {
  if (!options.packageName) {
    console.error('ioc check requires a package name');
    return 1;
  }

  const builtinMatch = BUILTIN_IOCS.find((ioc) => ioc.packageName === options.packageName);
  if (builtinMatch) {
    console.log(`MATCH [built-in] ${builtinMatch.packageName}`);
    console.log(`  reason: ${builtinMatch.reason}`);
    console.log(`  advisory: ${builtinMatch.advisory}`);
    return 1;
  }

  const customMatch = (config.customIocs ?? []).find((ioc) => ioc.packageName === options.packageName);
  if (customMatch) {
    console.log(`MATCH [custom] ${customMatch.packageName}`);
    console.log(`  reason: ${customMatch.reason}`);
    if (customMatch.advisory) console.log(`  advisory: ${customMatch.advisory}`);
    return 1;
  }

  console.log(`No IOC match for: ${options.packageName}`);
  return 0;
}

function isValidPackageName(name: string): boolean {
  if (name.startsWith('@')) {
    return /^@[a-z0-9][\w.-]*\/[a-z0-9][\w.-]*$/.test(name);
  }
  return /^[a-z0-9][\w.-]*$/.test(name);
}

function resolveConfigPath(rootDir: string, configPath?: string): string {
  return configPath
    ? path.resolve(rootDir, configPath)
    : path.join(path.resolve(rootDir), 'guardrail.config.json');
}

function loadConfigFile(configPath: string): Record<string, unknown> {
  if (!fs.existsSync(configPath)) {
    return {};
  }
  return parseJsonc<Record<string, unknown>>(fs.readFileSync(configPath, 'utf8'));
}
