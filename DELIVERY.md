# GuardRail delivery
## Threat model synthesis
### Root cause taxonomy
- parallel publish paths: OIDC trusted publishing reduces risk, but it does not remove manual or token-based publishing unless package settings explicitly disallow tokens
- install-time code execution: lifecycle hooks remain a silent remote-code-execution surface during dependency installation
- baseline blindness: the ecosystem has no native control for “this mature package suddenly gained a brand-new dependency”
- provenance non-enforcement: provenance and signatures help only when consumers verify them and reject regressions
- credential hygiene gaps: maintainer and CI environments still accumulate publish credentials and read tokens that are easier to steal than OIDC identity

### Attack surface map
- maintainer workstation and local `npm login` sessions
- `.npmrc` files, environment variables, and CI secret stores
- package registry publish permissions and package-level publishing access settings
- lockfile updates that bring in previously unseen transitive dependencies
- lifecycle hooks executed by `npm install`, `npm ci`, `pnpm install`, `yarn install`, and Bun equivalents
- source-review blind spots where malicious behavior is hidden in dependency metadata instead of application code

### Gap analysis of existing tools
- advisory-driven tools are reactive; they need a known bad version or a published advisory
- provenance tooling answers “was this built in a trusted environment?” but not “should I reject this release because the publish path changed?”
- CI runner hardening is strong inside CI, but not on developer machines and not on the registry itself
- no common tool combines dependency baselining, import-graph-aware ghost dependency detection, lifecycle script auditing, token hygiene, live registry monitoring, and incident workflow support in one path

### Recommended solution architecture
- signed historical baseline for packages you already trust
- import-graph-aware dependency mutation detection
- lifecycle script inventory plus risk scoring before install-time execution
- token scanning that treats OIDC-plus-token coexistence as a first-class policy failure
- package verification that compares publish path, provenance presence, and source-vs-tarball integrity
- live change-feed monitoring scoped to your dependency set
- incident response helpers that connect package exposure windows to CI logs and reachable secrets

## 1. Project Structure
```text
guardrail-security/
├── .github/
│   └── workflows/
│       └── guardrail.yml
├── INSTALL.md
├── README.md
├── DELIVERY.md
├── guardrail.config.json
├── package.json
├── src/
│   ├── commands/
│   │   ├── audit-tokens.ts
│   │   ├── incident.ts
│   │   ├── monitor.ts
│   │   ├── scan.ts
│   │   └── verify.ts
│   ├── core/
│   │   ├── baseline.ts
│   │   ├── npm-feed.ts
│   │   ├── provenance.ts
│   │   ├── script-analyzer.ts
│   │   └── token-scanner.ts
│   ├── index.ts
│   ├── integrations/
│   │   ├── github-actions.ts
│   │   ├── sarif.ts
│   │   └── slack.ts
│   ├── types/
│   │   ├── index.ts
│   │   └── node-shims.d.ts
│   └── utils/
│       ├── lockfile.ts
│       └── registry.ts
└── tsconfig.json
```

Additional supporting file used for TypeScript portability in strict mode: `src/types/node-shims.d.ts`.

## 2. package.json
```jsonc
{
  "name": "guardrail-security",
  "version": "0.1.0",
  "description": "GuardRail is an npm supply chain security guardian that detects dependency mutation, ghost dependencies, risky lifecycle scripts, token exposure, provenance gaps, and rapid-release anomalies.",
  "license": "MIT",
  "type": "commonjs",
  "main": "./dist/src/index.js",
  "bin": {
    "guardrail": "./dist/src/index.js",
    "guardrail-security": "./dist/src/index.js"
  },
  "files": [
    "dist",
    "README.md",
    "INSTALL.md",
    "guardrail.config.json",
    ".github/workflows/guardrail.yml"
  ],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "clean": "node -e \"require('fs').rmSync('dist',{recursive:true,force:true})\"",
    "start": "node ./dist/src/index.js",
    "scan": "node ./dist/src/index.js scan",
    "monitor": "node ./dist/src/index.js monitor",
    "audit-tokens": "node ./dist/src/index.js audit-tokens",
    "verify": "node ./dist/src/index.js verify",
    "incident": "node ./dist/src/index.js incident"
  },
  "engines": {
    "node": ">=20.0.0"
  },
  "keywords": [
    "npm",
    "security",
    "supply-chain",
    "provenance",
    "slsa",
    "sigstore",
    "token-security",
    "postinstall",
    "guardrail"
  ],
  "repository": {
    "type": "git",
    "url": "git+https://github.com/guardrail-security/guardrail.git"
  },
  "bugs": {
    "url": "https://github.com/guardrail-security/guardrail/issues"
  },
  "homepage": "https://github.com/guardrail-security/guardrail#readme",
  "devDependencies": {
    "@types/node": "^22.13.4",
    "typescript": "^5.8.3"
  }
}
```

## 3. tsconfig.json
```jsonc
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "moduleResolution": "Node",
    "outDir": "dist",
    "rootDir": ".",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "lib": ["ES2022", "DOM"],
    "declaration": false
  },
  "include": [
    "src/**/*.ts",
    "src/**/*.d.ts"
  ],
  "exclude": [
    "dist",
    "node_modules"
  ]
}
```

## 4. src/index.ts
```ts
#!/usr/bin/env node

import * as fs from 'node:fs';
import * as path from 'node:path';

import { runAuditTokens } from './commands/audit-tokens';
import { runIncident } from './commands/incident';
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
```

## 5. src/commands/scan.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';

import { generateGuardrailWorkflow } from '../integrations/github-actions';
import { writeSarif } from '../integrations/sarif';
import {
  BaselineSnapshot,
  GuardrailConfig,
  LockfileInfo,
  PackageNode,
  PackageSnapshot,
  ScanCommandOptions,
  ScanExecutionResult,
  ScanIssue,
} from '../types';
import {
  latestSnapshotForPackage,
  loadBaseline,
  mergeSnapshots,
  severityToNumber,
  sha256,
  snapshotKey,
  writeBaseline,
} from '../core/baseline';
import {
  analyzeLifecycleScripts,
  hashLifecycleScripts,
  highestScriptRisk,
  pickLifecycleScripts,
} from '../core/script-analyzer';
import { parseLockfile } from '../utils/lockfile';

const SOURCE_FILE_PATTERN = /\.(?:[cm]?[jt]sx?|json)$/i;
const PACKAGE_SCAN_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'coverage',
  '.nyc_output',
  'test',
  'tests',
  '__tests__',
  'docs',
  'examples',
  'example',
]);

export async function runScan(
  options: ScanCommandOptions,
  config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    throw new Error(`No package.json found in ${rootDir}`);
  }

  const rootManifestText = fs.readFileSync(packageJsonPath, 'utf8');
  const rootManifest = JSON.parse(rootManifestText) as Record<string, unknown>;
  const lockfile = parseLockfile(rootDir);
  const installedPackages = collectInstalledPackageSnapshots(rootDir, config);
  const packageMap = mergeInstalledAndLockfilePackages(lockfile, installedPackages);
  const lifecycleScriptsDiscovered = Object.values(packageMap).reduce(
    (count, entry) => count + Object.keys(entry.lifecycleScripts).length,
    0,
  );

  const rootManifestHash = sha256(rootManifestText);
  const lockfileHash = lockfile.path && fs.existsSync(lockfile.path)
    ? sha256(fs.readFileSync(lockfile.path, 'utf8'))
    : undefined;

  const baselineResult = loadBaseline(rootDir, config);
  const currentSnapshot: BaselineSnapshot = {
    generatedAt: new Date().toISOString(),
    rootManifestHash,
    lockfileHash,
    packageManager: lockfile.kind,
    packages: packageMap,
  };

  let baselineCreated = false;
  let baselineVerified = baselineResult.verified;
  let previousSnapshot = baselineResult.baseline?.snapshot;

  if (!baselineResult.baseline) {
    baselineCreated = true;
    baselineVerified = true;
  }

  const trustedPackages = new Set<string>([
    ...Object.keys(toRecord(rootManifest.dependencies)),
    ...(config.scan?.trustedPackages ?? []),
  ]);
  const threshold = options.threshold ?? config.scan?.riskThreshold ?? 70;
  const issues = compareSnapshots(previousSnapshot, currentSnapshot, trustedPackages, threshold);

  const mergedSnapshot = mergeSnapshots(
    previousSnapshot,
    currentSnapshot.packages,
    currentSnapshot.rootManifestHash,
    currentSnapshot.lockfileHash,
    currentSnapshot.packageManager,
  );

  if (baselineCreated || options.updateBaseline) {
    writeBaseline(rootDir, config, mergedSnapshot, baselineResult.baseline);
    previousSnapshot = mergedSnapshot;
  }

  if (options.generateWorkflow) {
    writeWorkflow(rootDir);
  }

  if (options.installPreCommit) {
    installPreCommitHook(rootDir);
  }

  if (options.sarif) {
    writeSarif(path.resolve(rootDir, options.sarif), issues);
  }

  const result: ScanExecutionResult = {
    rootDir,
    generatedAt: currentSnapshot.generatedAt,
    baselinePath: baselineResult.path,
    baselineVerified,
    baselineCreated,
    lockfile,
    packagesScanned: Object.keys(packageMap).length,
    lifecycleScriptsDiscovered,
    issues,
    packages: packageMap,
  };

  if (options.output) {
    fs.writeFileSync(path.resolve(rootDir, options.output), `${JSON.stringify(result, null, 2)}\n`);
  }

  if (!options.quiet) {
    printScanResult(result, threshold, options.updateBaseline === true);
  }

  const failSeverity = severityToNumber(config.scan?.failOnSeverity ?? 'high');
  const shouldFail = Boolean(options.failFast) && issues.some((issue) => severityToNumber(issue.severity) >= failSeverity);
  return shouldFail ? 1 : 0;
}

function compareSnapshots(
  previous: BaselineSnapshot | undefined,
  current: BaselineSnapshot,
  trustedPackages: Set<string>,
  threshold: number,
): ScanIssue[] {
  const issues: ScanIssue[] = [];

  for (const currentPackage of Object.values(current.packages)) {
    const key = snapshotKey(currentPackage.name, currentPackage.version);
    const previousExact = previous?.packages[key];
    const previousByName = previous ? latestSnapshotForPackage(previous, currentPackage.name) : undefined;

    if (previousExact && previousExact.packageHash !== currentPackage.packageHash) {
      issues.push({
        id: `${key}:hash-changed`,
        code: 'GR_TAMPERED_VERSION',
        category: 'integrity',
        severity: 'critical',
        title: 'Package contents changed for a version already in the baseline',
        description:
          'The same package version now resolves to different manifest or source content than the signed baseline recorded earlier.',
        packageName: currentPackage.name,
        packageVersion: currentPackage.version,
        recommendation:
          'Treat this as a registry or cache integrity incident. Re-fetch from a clean environment and verify the upstream package tarball.',
      });
    }

    if (previousByName && previousByName.version !== currentPackage.version) {
      const newDependencies = currentPackage.declaredDependencies.filter(
        (dependency) => !previousByName.declaredDependencies.includes(dependency),
      );
      const addedScripts = Object.keys(currentPackage.lifecycleScripts).filter(
        (scriptName) => !(scriptName in previousByName.lifecycleScripts),
      );
      const changedScripts = Object.keys(currentPackage.lifecycleScripts).filter(
        (scriptName) => previousByName.lifecycleScripts[scriptName] !== undefined && previousByName.lifecycleScripts[scriptName] !== currentPackage.lifecycleScripts[scriptName],
      );

      if (newDependencies.length > 0) {
        const severity = trustedPackages.has(currentPackage.name) ? 'high' : 'medium';
        issues.push({
          id: `${key}:new-dependencies`,
          code: 'GR_DEPENDENCY_MUTATION',
          category: 'mutation',
          severity,
          title: 'Previously known package introduced new dependencies',
          description:
            `${currentPackage.name}@${currentPackage.version} added dependencies that were not present in the baseline for ${previousByName.version}.`,
          packageName: currentPackage.name,
          packageVersion: currentPackage.version,
          evidence: [
            `previous version: ${previousByName.version}`,
            `new dependencies: ${newDependencies.join(', ')}`,
          ],
          recommendation:
            'Review the package diff before allowing installation. Sudden dependency expansion on mature packages is a high-value supply chain signal.',
        });
      }

      if (currentPackage.sourceFileCount > 0) {
        const ghostDependencies = newDependencies.filter((dependency) =>
          currentPackage.unusedDeclaredDependencies.includes(dependency),
        );
        if (ghostDependencies.length > 0) {
          issues.push({
            id: `${key}:ghost-dependencies`,
            code: 'GR_GHOST_DEPENDENCY',
            category: 'ghost-dependency',
            severity: trustedPackages.has(currentPackage.name) ? 'critical' : 'high',
            title: 'New dependencies are declared but not imported by package source',
            description:
              `${currentPackage.name}@${currentPackage.version} introduced dependencies that do not appear in the package source import graph. This matches the ghost dependency pattern used to hide postinstall droppers.`,
            packageName: currentPackage.name,
            packageVersion: currentPackage.version,
            evidence: [
              `ghost dependencies: ${ghostDependencies.join(', ')}`,
              `baseline version: ${previousByName.version}`,
            ],
            recommendation:
              'Block installation until the maintainer explains the dependency and the package tarball is manually reviewed.',
          });
        }
      }

      if (addedScripts.length > 0 || changedScripts.length > 0) {
        issues.push({
          id: `${key}:lifecycle-changed`,
          code: 'GR_LIFECYCLE_SCRIPT_DELTA',
          category: 'lifecycle-script',
          severity: 'high',
          title: 'Lifecycle scripts were added or changed',
          description:
            `${currentPackage.name}@${currentPackage.version} changed install-time lifecycle scripts compared with the signed baseline.`,
          packageName: currentPackage.name,
          packageVersion: currentPackage.version,
          evidence: [
            `added scripts: ${addedScripts.join(', ') || 'none'}`,
            `changed scripts: ${changedScripts.join(', ') || 'none'}`,
          ],
          recommendation:
            'Treat new or changed install scripts as code execution events. Review the script body and any referenced files before continuing.',
        });
      }
    }

    for (const finding of currentPackage.scriptFindings) {
      if (finding.score < threshold) {
        continue;
      }
      issues.push({
        id: `${key}:${finding.scriptName}`,
        code: 'GR_RISKY_LIFECYCLE_SCRIPT',
        category: 'lifecycle-script',
        severity: finding.severity,
        title: 'Lifecycle script exceeded the GuardRail risk threshold',
        description:
          `${currentPackage.name}@${currentPackage.version} has a ${finding.scriptName} script with risk score ${String(finding.score)}.`,
        packageName: currentPackage.name,
        packageVersion: currentPackage.version,
        score: finding.score,
        evidence: [...finding.reasons, ...finding.evidence].slice(0, 12),
        recommendation:
          'Run installs with --ignore-scripts until the package is reviewed. Investigate network access, file writes, obfuscation, and script-spawn behavior in the lifecycle hook.',
      });
    }
  }

  return issues.sort((left, right) => severityToNumber(right.severity) - severityToNumber(left.severity));
}

function mergeInstalledAndLockfilePackages(
  lockfile: LockfileInfo,
  installedPackages: Record<string, PackageSnapshot>,
): Record<string, PackageSnapshot> {
  const merged: Record<string, PackageSnapshot> = { ...installedPackages };

  for (const node of lockfile.packages) {
    const key = snapshotKey(node.name, node.version);
    if (merged[key]) {
      continue;
    }
    merged[key] = buildMinimalSnapshotFromLockfile(node);
  }

  return merged;
}

function buildMinimalSnapshotFromLockfile(node: PackageNode): PackageSnapshot {
  const declaredDependencies = Object.keys(node.dependencies).sort();
  return {
    name: node.name,
    version: node.version,
    packagePath: node.path,
    declaredDependencies,
    optionalDependencies: [],
    peerDependencies: [],
    importedDependencies: [],
    unusedDeclaredDependencies: [],
    lifecycleScripts: {},
    lifecycleScriptHashes: {},
    scriptFindings: [],
    highestScriptRisk: 0,
    sourceFileCount: 0,
    manifestHash: sha256(JSON.stringify(node.dependencies)),
    sourceHash: sha256(`${node.name}@${node.version}`),
    packageHash: sha256(JSON.stringify(node)),
  };
}

function collectInstalledPackageSnapshots(
  rootDir: string,
  config: GuardrailConfig,
): Record<string, PackageSnapshot> {
  const snapshots: Record<string, PackageSnapshot> = {};
  const rootNodeModules = path.join(rootDir, 'node_modules');
  if (!fs.existsSync(rootNodeModules)) {
    return snapshots;
  }

  const visitedPackageDirs = new Set<string>();
  const visitedContainers = new Set<string>();

  const visitContainer = (containerPath: string): void => {
    const realContainer = safeRealpath(containerPath);
    if (!realContainer || visitedContainers.has(realContainer) || !fs.existsSync(containerPath)) {
      return;
    }
    visitedContainers.add(realContainer);

    for (const entry of fs.readdirSync(containerPath)) {
      if (entry === '.bin') {
        continue;
      }
      const entryPath = path.join(containerPath, entry);
      if (!isDirectory(entryPath)) {
        continue;
      }

      if (entry === '.pnpm') {
        for (const nested of fs.readdirSync(entryPath)) {
          const nestedNodeModules = path.join(entryPath, nested, 'node_modules');
          if (fs.existsSync(nestedNodeModules)) {
            visitContainer(nestedNodeModules);
          }
        }
        continue;
      }

      if (entry.startsWith('@')) {
        for (const scopedEntry of fs.readdirSync(entryPath)) {
          const packageDir = path.join(entryPath, scopedEntry);
          if (fs.existsSync(path.join(packageDir, 'package.json'))) {
            processPackageDir(packageDir);
          }
        }
        continue;
      }

      if (fs.existsSync(path.join(entryPath, 'package.json'))) {
        processPackageDir(entryPath);
      }
    }
  };

  const processPackageDir = (packageDir: string): void => {
    const realPackageDir = safeRealpath(packageDir);
    if (!realPackageDir || visitedPackageDirs.has(realPackageDir)) {
      return;
    }
    visitedPackageDirs.add(realPackageDir);

    const snapshot = analyzeInstalledPackage(packageDir, config);
    if (snapshot) {
      snapshots[snapshotKey(snapshot.name, snapshot.version)] = snapshot;
    }

    const nestedNodeModules = path.join(packageDir, 'node_modules');
    if (fs.existsSync(nestedNodeModules)) {
      visitContainer(nestedNodeModules);
    }
  };

  visitContainer(rootNodeModules);
  return snapshots;
}

function analyzeInstalledPackage(
  packageDir: string,
  config: GuardrailConfig,
): PackageSnapshot | null {
  const manifestPath = path.join(packageDir, 'package.json');
  if (!fs.existsSync(manifestPath)) {
    return null;
  }

  try {
    const manifestText = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestText) as Record<string, unknown>;
    const name = typeof manifest.name === 'string' ? manifest.name : undefined;
    const version = typeof manifest.version === 'string' ? manifest.version : undefined;
    if (!name || !version) {
      return null;
    }

    const declaredDependencies = Object.keys(toRecord(manifest.dependencies)).sort();
    const optionalDependencies = Object.keys(toRecord(manifest.optionalDependencies)).sort();
    const peerDependencies = Object.keys(toRecord(manifest.peerDependencies)).sort();
    const lifecycleScripts = pickLifecycleScripts(normalizeScriptRecord(manifest.scripts));
    const importedDependencies = Array.from(scanImportsInDirectory(packageDir, config)).sort();
    const unusedDeclaredDependencies = declaredDependencies.filter(
      (dependency) => !importedDependencies.includes(dependency),
    );
    const scriptFindings = analyzeLifecycleScripts(name, version, lifecycleScripts, (relativePath) =>
      readLocalScriptFile(packageDir, relativePath, config.scan?.maxScriptFileBytes ?? 256000),
    );

    const sourceHashes = collectSourceHashes(packageDir, config);
    const sourceHash = sha256(sourceHashes.join('\n'));
    const manifestHash = sha256(manifestText);

    return {
      name,
      version,
      packagePath: packageDir,
      declaredDependencies,
      optionalDependencies,
      peerDependencies,
      importedDependencies,
      unusedDeclaredDependencies,
      lifecycleScripts,
      lifecycleScriptHashes: hashLifecycleScripts(lifecycleScripts),
      scriptFindings,
      highestScriptRisk: highestScriptRisk(scriptFindings),
      sourceFileCount: sourceHashes.length,
      manifestHash,
      sourceHash,
      packageHash: sha256([manifestHash, sourceHash, JSON.stringify(lifecycleScripts)].join(':')),
    };
  } catch {
    return null;
  }
}

function scanImportsInDirectory(packageDir: string, config: GuardrailConfig): Set<string> {
  const imports = new Set<string>();
  for (const filePath of listSourceFiles(packageDir, config)) {
    const text = fs.readFileSync(filePath, 'utf8');
    for (const specifier of extractModuleSpecifiers(text)) {
      const packageName = normalizeModuleSpecifier(specifier);
      if (packageName) {
        imports.add(packageName);
      }
    }
  }
  return imports;
}

function listSourceFiles(packageDir: string, config: GuardrailConfig): string[] {
  const files: string[] = [];
  const ignored = new Set([...(config.scan?.ignoreDirs ?? []), ...PACKAGE_SCAN_IGNORE_DIRS]);
  const stack = [packageDir];
  const maxFiles = 800;

  while (stack.length > 0 && files.length < maxFiles) {
    const currentDir = stack.pop() as string;
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const entryPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (ignored.has(entry.name)) {
          continue;
        }
        stack.push(entryPath);
        continue;
      }
      if (!entry.isFile() || !SOURCE_FILE_PATTERN.test(entry.name)) {
        continue;
      }
      const stats = fs.statSync(entryPath);
      if (stats.size > 512000) {
        continue;
      }
      files.push(entryPath);
      if (files.length >= maxFiles) {
        break;
      }
    }
  }

  return files;
}

function collectSourceHashes(packageDir: string, config: GuardrailConfig): string[] {
  return listSourceFiles(packageDir, config)
    .map((filePath) => `${path.relative(packageDir, filePath)}:${sha256(fs.readFileSync(filePath))}`)
    .sort();
}

function readLocalScriptFile(packageDir: string, relativePath: string, maxBytes: number): string | undefined {
  const candidate = path.join(packageDir, relativePath.replace(/^\.\//, ''));
  if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) {
    return undefined;
  }
  const stats = fs.statSync(candidate);
  if (stats.size > maxBytes) {
    return undefined;
  }
  return fs.readFileSync(candidate, 'utf8');
}

function extractModuleSpecifiers(source: string): string[] {
  const patterns = [
    /import\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
    /import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /export\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
  ];

  const result: string[] = [];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null = pattern.exec(source);
    while (match) {
      if (match[1]) {
        result.push(match[1]);
      }
      match = pattern.exec(source);
    }
  }
  return result;
}

function normalizeModuleSpecifier(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {
    return undefined;
  }
  const segments = specifier.split('/').filter(Boolean);
  if (segments.length === 0) {
    return undefined;
  }
  if (segments[0]?.startsWith('@') && segments[1]) {
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0];
}

function normalizeScriptRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawCommand] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawCommand === 'string') {
      result[name] = rawCommand;
    }
  }
  return result;
}

function toRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (typeof raw === 'string') {
      result[key] = raw;
    }
  }
  return result;
}

function safeRealpath(candidate: string): string | null {
  try {
    return fs.realpathSync(candidate);
  } catch {
    return null;
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function installPreCommitHook(rootDir: string): void {
  const hookPath = path.join(rootDir, '.git', 'hooks', 'pre-commit');
  fs.mkdirSync(path.dirname(hookPath), { recursive: true });
  fs.writeFileSync(
    hookPath,
    '#!/usr/bin/env sh\nset -eu\nif command -v guardrail >/dev/null 2>&1; then\n  guardrail scan --fail-fast --quiet\nelse\n  npx guardrail-security scan --fail-fast --quiet\nfi\n',
    { mode: 0o755 },
  );
}

function writeWorkflow(rootDir: string): void {
  const workflowPath = path.join(rootDir, '.github', 'workflows', 'guardrail.yml');
  fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
  fs.writeFileSync(workflowPath, generateGuardrailWorkflow());
}

function printScanResult(result: ScanExecutionResult, threshold: number, baselineWasUpdated: boolean): void {
  console.log(`GuardRail scan`);
  console.log(`root: ${result.rootDir}`);
  console.log(`baseline: ${result.baselinePath} (${result.baselineCreated ? 'created' : result.baselineVerified ? 'verified' : 'unverified'})`);
  console.log(`lockfile: ${result.lockfile.kind}${result.lockfile.path ? ` (${result.lockfile.path})` : ''}`);
  console.log(`packages scanned: ${String(result.packagesScanned)}`);
  console.log(`lifecycle scripts discovered: ${String(result.lifecycleScriptsDiscovered)}`);
  console.log(`risk threshold: ${String(threshold)}`);
  if (baselineWasUpdated || result.baselineCreated) {
    console.log(`baseline updated: yes`);
  }

  for (const warning of result.lockfile.warnings) {
    console.log(`warning: ${warning}`);
  }

  console.log('');
  console.log('Lifecycle script inventory:');
  const scriptLines = Object.values(result.packages)
    .flatMap((pkg) =>
      Object.entries(pkg.lifecycleScripts).map(([name, command]) => {
        const score = pkg.scriptFindings.find((finding) => finding.scriptName === name)?.score ?? 0;
        return `- ${pkg.name}@${pkg.version} ${name} [score=${String(score)}] ${command}`;
      }),
    )
    .sort();

  if (scriptLines.length === 0) {
    console.log('- none');
  } else {
    for (const line of scriptLines) {
      console.log(line);
    }
  }

  console.log('');
  console.log(`Findings: ${String(result.issues.length)}`);
  if (result.issues.length === 0) {
    console.log('- no findings above current policy');
    return;
  }

  for (const issue of result.issues) {
    const pkg = issue.packageName && issue.packageVersion ? ` ${issue.packageName}@${issue.packageVersion}` : '';
    console.log(`- [${issue.severity}] ${issue.code}${pkg}: ${issue.title}`);
    console.log(`  ${issue.description}`);
    if (issue.evidence && issue.evidence.length > 0) {
      console.log(`  evidence: ${issue.evidence.join(' | ')}`);
    }
    if (issue.recommendation) {
      console.log(`  action: ${issue.recommendation}`);
    }
  }
}
```

## 6. src/commands/monitor.ts
```ts
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import * as tls from 'node:tls';

import { MonitorAlert, MonitorCommandOptions, GuardrailConfig, PackageSnapshot } from '../types';
import { NpmFeedSubscriber } from '../core/npm-feed';
import {
  analyzeRegistryPackage,
  hasProvenanceSignal,
  inferPublishMethod,
} from '../core/provenance';
import { sendSlackAlert } from '../integrations/slack';
import { fetchPackageVersion } from '../utils/registry';

interface PackageState {
  version: string;
  snapshot: PackageSnapshot;
  publishMethod: MonitorAlert['publishMethod'];
  publishedBy?: string;
  publisherEmail?: string;
  hasTrustedPublisher: boolean;
  hasProvenance: boolean;
}

export async function runMonitor(
  options: MonitorCommandOptions,
  config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const packagesToWatch = determinePackagesToWatch(rootDir, config);
  if (packagesToWatch.size === 0) {
    throw new Error('No packages were available to watch. Add dependencies or set monitor.packages in guardrail.config.json.');
  }

  const states = new Map<string, PackageState>();
  for (const packageName of packagesToWatch) {
    try {
      const metadata = await fetchPackageVersion(packageName);
      const analysis = await analyzeRegistryPackage(packageName, metadata.version);
      states.set(packageName, {
        version: metadata.version,
        snapshot: analysis.snapshot,
        publishMethod: inferPublishMethod(metadata),
        publishedBy: metadata._npmUser?.name,
        publisherEmail: metadata._npmUser?.email,
        hasTrustedPublisher: inferPublishMethod(metadata) === 'trusted-publishing',
        hasProvenance: hasProvenanceSignal(metadata),
      });
    } catch (error) {
      console.log(`warning: could not seed state for ${packageName}: ${formatError(error)}`);
    }
  }

  console.log(`GuardRail monitor watching ${String(packagesToWatch.size)} package(s)`);
  console.log(`packages: ${Array.from(packagesToWatch).sort().join(', ')}`);

  const subscriber = new NpmFeedSubscriber(options.intervalMs ?? config.monitor?.pollIntervalMs ?? 25000);
  await subscriber.watch(
    packagesToWatch,
    async (change) => {
      try {
        const metadata = await fetchPackageVersion(change.packageName);
        const previous = states.get(change.packageName);
        if (previous && previous.version === metadata.version) {
          return;
        }

        const analysis = await analyzeRegistryPackage(change.packageName, metadata.version);
        const publishMethod = inferPublishMethod(metadata);
        const hasTrustedPublisher = publishMethod === 'trusted-publishing';
        const hasProvenance = hasProvenanceSignal(metadata);
        const alert = buildAlert(previous, analysis.snapshot, {
          version: metadata.version,
          publishMethod,
          publishedBy: metadata._npmUser?.name,
          publisherEmail: metadata._npmUser?.email,
          hasTrustedPublisher,
          hasProvenance,
        });

        printAlert(alert);
        await notify(alert, options, config);

        states.set(change.packageName, {
          version: metadata.version,
          snapshot: analysis.snapshot,
          publishMethod,
          publishedBy: metadata._npmUser?.name,
          publisherEmail: metadata._npmUser?.email,
          hasTrustedPublisher,
          hasProvenance,
        });
      } catch (error) {
        console.log(`warning: failed to inspect ${change.packageName}: ${formatError(error)}`);
      }
    },
    { once: options.once },
  );

  return 0;
}

function determinePackagesToWatch(rootDir: string, config: GuardrailConfig): Set<string> {
  if (Array.isArray(config.monitor?.packages) && config.monitor?.packages.length > 0) {
    return new Set(config.monitor.packages);
  }

  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    return new Set<string>();
  }

  const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as Record<string, unknown>;
  const dependencies = Object.keys(asRecord(parsed.dependencies));
  const optionalDependencies = Object.keys(asRecord(parsed.optionalDependencies));
  return new Set([...dependencies, ...optionalDependencies]);
}

function buildAlert(
  previous: PackageState | undefined,
  current: PackageSnapshot,
  metadata: Omit<PackageState, 'snapshot'>,
): MonitorAlert {
  const previousSnapshot = previous?.snapshot;
  const newDependencies = previousSnapshot
    ? current.declaredDependencies.filter((dependency) => !previousSnapshot.declaredDependencies.includes(dependency))
    : current.declaredDependencies;
  const removedDependencies = previousSnapshot
    ? previousSnapshot.declaredDependencies.filter((dependency) => !current.declaredDependencies.includes(dependency))
    : [];
  const addedLifecycleScripts = previousSnapshot
    ? Object.keys(current.lifecycleScripts).filter((scriptName) => !(scriptName in previousSnapshot.lifecycleScripts))
    : Object.keys(current.lifecycleScripts);
  const changedLifecycleScripts = previousSnapshot
    ? Object.keys(current.lifecycleScripts).filter(
        (scriptName) => previousSnapshot.lifecycleScripts[scriptName] !== undefined && previousSnapshot.lifecycleScripts[scriptName] !== current.lifecycleScripts[scriptName],
      )
    : [];
  const ghostDependencies = newDependencies.filter((dependency) => current.unusedDeclaredDependencies.includes(dependency));

  const reasons: string[] = [];
  if (previous && previous.publishMethod === 'trusted-publishing' && metadata.publishMethod !== 'trusted-publishing') {
    reasons.push('publish path regressed from trusted publishing to manual-or-token');
  }
  if (previous && previous.publishedBy && metadata.publishedBy && previous.publishedBy !== metadata.publishedBy) {
    reasons.push(`publisher changed from ${previous.publishedBy} to ${metadata.publishedBy}`);
  }
  if (newDependencies.length > 0) {
    reasons.push(`new dependencies: ${newDependencies.join(', ')}`);
  }
  if (ghostDependencies.length > 0) {
    reasons.push(`ghost dependencies: ${ghostDependencies.join(', ')}`);
  }
  if (addedLifecycleScripts.length > 0 || changedLifecycleScripts.length > 0) {
    reasons.push('lifecycle scripts were added or changed');
  }
  if (current.highestScriptRisk >= 70) {
    reasons.push(`lifecycle script risk score ${String(current.highestScriptRisk)}`);
  }
  if (previous?.hasProvenance && !metadata.hasProvenance) {
    reasons.push('provenance signal disappeared');
  }

  return {
    occurredAt: new Date().toISOString(),
    packageName: current.name,
    previousVersion: previous?.version,
    version: metadata.version,
    publishedBy: metadata.publishedBy,
    publisherEmail: metadata.publisherEmail,
    publishMethod: metadata.publishMethod,
    hasTrustedPublisher: metadata.hasTrustedPublisher,
    hasProvenance: metadata.hasProvenance,
    newDependencies,
    removedDependencies,
    addedLifecycleScripts,
    changedLifecycleScripts,
    ghostDependencies,
    scriptRiskScore: current.highestScriptRisk,
    scriptFindings: current.scriptFindings,
    suspicious: reasons.length > 0,
    reasons,
  };
}

function printAlert(alert: MonitorAlert): void {
  console.log('');
  console.log(`GuardRail alert ${alert.packageName}@${alert.version}`);
  console.log(`time: ${alert.occurredAt}`);
  console.log(`previous: ${alert.previousVersion ?? 'unknown'}`);
  console.log(`publish method: ${alert.publishMethod}`);
  console.log(`publisher: ${alert.publishedBy ?? 'unknown'}${alert.publisherEmail ? ` <${alert.publisherEmail}>` : ''}`);
  console.log(`trusted publisher: ${alert.hasTrustedPublisher ? 'yes' : 'no'}`);
  console.log(`provenance: ${alert.hasProvenance ? 'present' : 'missing'}`);
  console.log(`new dependencies: ${alert.newDependencies.join(', ') || 'none'}`);
  console.log(`added lifecycle scripts: ${alert.addedLifecycleScripts.join(', ') || 'none'}`);
  console.log(`changed lifecycle scripts: ${alert.changedLifecycleScripts.join(', ') || 'none'}`);
  console.log(`ghost dependencies: ${alert.ghostDependencies.join(', ') || 'none'}`);
  console.log(`script risk score: ${String(alert.scriptRiskScore)}`);
  console.log(`reasons: ${alert.reasons.join('; ') || 'no suspicious deltas'}`);
}

async function notify(
  alert: MonitorAlert,
  options: MonitorCommandOptions,
  config: GuardrailConfig,
): Promise<void> {
  const slackWebhook = options.slackWebhook ?? config.monitor?.slackWebhook ?? config.notifications?.slackWebhook;
  if (slackWebhook) {
    try {
      await sendSlackAlert(slackWebhook, alert);
    } catch (error) {
      console.log(`warning: slack notification failed: ${formatError(error)}`);
    }
  }

  const webhook = options.webhook ?? config.monitor?.webhook ?? config.notifications?.webhook;
  if (webhook) {
    try {
      const response = await fetch(webhook, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(alert),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      console.log(`warning: webhook notification failed: ${formatError(error)}`);
    }
  }

  const emailConfig = config.monitor?.email ?? config.notifications?.email;
  if (emailConfig) {
    try {
      await sendSmtpEmail(
        emailConfig,
        `[GuardRail] ${alert.packageName}@${alert.version}`,
        [
          `Package: ${alert.packageName}@${alert.version}`,
          `Previous version: ${alert.previousVersion ?? 'unknown'}`,
          `Publish method: ${alert.publishMethod}`,
          `Publisher: ${alert.publishedBy ?? 'unknown'}${alert.publisherEmail ? ` <${alert.publisherEmail}>` : ''}`,
          `Trusted publisher: ${alert.hasTrustedPublisher ? 'yes' : 'no'}`,
          `Provenance: ${alert.hasProvenance ? 'present' : 'missing'}`,
          `New dependencies: ${alert.newDependencies.join(', ') || 'none'}`,
          `Added lifecycle scripts: ${alert.addedLifecycleScripts.join(', ') || 'none'}`,
          `Changed lifecycle scripts: ${alert.changedLifecycleScripts.join(', ') || 'none'}`,
          `Ghost dependencies: ${alert.ghostDependencies.join(', ') || 'none'}`,
          `Script risk score: ${String(alert.scriptRiskScore)}`,
          `Reasons: ${alert.reasons.join('; ') || 'no suspicious deltas'}`,
        ].join('\n'),
      );
    } catch (error) {
      console.log(`warning: email notification failed: ${formatError(error)}`);
    }
  }
}

async function sendSmtpEmail(
  config: {
    host: string;
    port: number;
    secure?: boolean;
    username?: string;
    password?: string;
    from: string;
    to: string[];
  },
  subject: string,
  body: string,
): Promise<void> {
  const socket = await connectSmtp(config.host, config.port, Boolean(config.secure));
  const session = new SmtpSession(socket);

  try {
    await session.readResponse([220]);
    await session.command(`EHLO guardrail.local`, [250]);

    if (config.username && config.password) {
      const authPayload = Buffer.from(`\u0000${config.username}\u0000${config.password}`).toString('base64');
      await session.command(`AUTH PLAIN ${authPayload}`, [235]);
    }

    await session.command(`MAIL FROM:<${config.from}>`, [250]);
    for (const recipient of config.to) {
      await session.command(`RCPT TO:<${recipient}>`, [250, 251]);
    }
    await session.command('DATA', [354]);

    const message = [
      `From: ${config.from}`,
      `To: ${config.to.join(', ')}`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      escapeSmtpBody(body),
      '.',
    ].join('\r\n');

    session.write(`${message}\r\n`);
    await session.readResponse([250]);
    await session.command('QUIT', [221]);
  } finally {
    socket.end();
  }
}

function escapeSmtpBody(body: string): string {
  return body
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((line) => (line.startsWith('.') ? `.${line}` : line))
    .join('\r\n');
}

async function connectSmtp(host: string, port: number, secure: boolean): Promise<any> {
  return new Promise((resolve, reject) => {
    const factory = secure ? tls.connect : net.connect;
    const socket = factory({ host, port }, () => resolve(socket));
    socket.once('error', reject);
  });
}

class SmtpSession {
  private buffer = '';
  private pending:
    | {
        expectedCodes: number[];
        resolve: (value: string) => void;
        reject: (error: unknown) => void;
      }
    | undefined;

  public constructor(private readonly socket: any) {
    this.socket.setEncoding('utf8');
    this.socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.flushIfComplete();
    });
  }

  public write(data: string): void {
    this.socket.write(data);
  }

  public async command(command: string, expectedCodes: number[]): Promise<string> {
    this.socket.write(`${command}\r\n`);
    return this.readResponse(expectedCodes);
  }

  public async readResponse(expectedCodes: number[]): Promise<string> {
    if (this.pending) {
      throw new Error('SMTP session already waiting for a response');
    }
    return new Promise((resolve, reject) => {
      this.pending = { expectedCodes, resolve, reject };
      this.flushIfComplete();
    });
  }

  private flushIfComplete(): void {
    if (!this.pending) {
      return;
    }

    const lines = this.buffer.split(/\r\n/).filter((line) => line.length > 0);
    if (lines.length === 0) {
      return;
    }

    const last = lines[lines.length - 1] ?? '';
    if (!/^\d{3} /.test(last)) {
      return;
    }

    const response = this.buffer;
    this.buffer = '';
    const pending = this.pending;
    this.pending = undefined;
    const matched = pending.expectedCodes.some((code) => new RegExp(`^${String(code)}[ -]`, 'm').test(response));
    if (!matched) {
      pending.reject(new Error(`Unexpected SMTP response: ${response.trim()}`));
      return;
    }
    pending.resolve(response);
  }
}

function asRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawValue === 'string') {
      result[key] = rawValue;
    }
  }
  return result;
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
```

## 7. src/commands/audit-tokens.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';

import { AuditTokensCommandOptions, GuardrailConfig } from '../types';
import { revokeSuggestedTokens, scanTokenExposure } from '../core/token-scanner';
import { severityToNumber } from '../core/baseline';

export async function runAuditTokens(
  options: AuditTokensCommandOptions,
  config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const result = await scanTokenExposure(rootDir, config);

  let revoked: string[] = [];
  if (options.revokeStale) {
    revoked = revokeSuggestedTokens(result.findings, options.staleAfterDays ?? config.tokenPolicy?.staleAfterDays ?? 30);
  }

  if (options.output) {
    fs.writeFileSync(path.resolve(rootDir, options.output), `${JSON.stringify({ ...result, revoked }, null, 2)}\n`);
  }

  if (options.json) {
    console.log(JSON.stringify({ ...result, revoked }, null, 2));
  } else {
    printHumanReadable(result, revoked);
  }

  const highest = result.issues.reduce(
    (max, issue) => Math.max(max, severityToNumber(issue.severity)),
    1,
  );
  return highest >= severityToNumber('high') ? 1 : 0;
}

function printHumanReadable(
  result: Awaited<ReturnType<typeof scanTokenExposure>>,
  revoked: string[],
): void {
  console.log('GuardRail token audit');
  console.log(`root: ${result.rootDir}`);
  console.log(`oidc trusted publishing detected: ${result.oidcTrustedPublishingDetected ? 'yes' : 'no'}`);
  console.log(`self-hosted runners detected: ${result.selfHostedRunnerDetected ? 'yes' : 'no'}`);
  console.log(`static publish tokens found: ${result.staticPublishTokensFound ? 'yes' : 'no'}`);
  console.log(`mixed mode risk: ${result.mixedModeRisk ? 'yes' : 'no'}`);
  console.log('');

  console.log('Discovered credentials:');
  if (result.findings.length === 0) {
    console.log('- none');
  } else {
    for (const finding of result.findings) {
      console.log(
        `- ${finding.sourceType} ${finding.sourcePath ?? finding.envVar ?? 'unknown'} -> ${finding.tokenKind} ${finding.tokenPreview}`,
      );
      if (finding.note) {
        console.log(`  note: ${finding.note}`);
      }
      if (finding.expiresAt) {
        console.log(`  expires: ${finding.expiresAt}`);
      }
      if (finding.id) {
        console.log(`  revoke: npm token revoke ${finding.id}`);
      }
    }
  }

  console.log('');
  console.log('Findings:');
  if (result.issues.length === 0) {
    console.log('- no token hygiene issues detected');
  } else {
    for (const issue of result.issues) {
      console.log(`- [${issue.severity}] ${issue.code}: ${issue.title}`);
      console.log(`  ${issue.description}`);
      if (issue.recommendation) {
        console.log(`  action: ${issue.recommendation}`);
      }
    }
  }

  if (result.suggestedRevocations.length > 0) {
    console.log('');
    console.log('Suggested revocations:');
    for (const command of result.suggestedRevocations) {
      console.log(`- ${command}`);
    }
  }

  if (revoked.length > 0) {
    console.log('');
    console.log(`Revoked tokens: ${revoked.join(', ')}`);
  }
}
```

## 8. src/commands/verify.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';

import { GuardrailConfig, VerifyCommandOptions } from '../types';
import { severityToNumber } from '../core/baseline';
import { verifyPackageProvenance } from '../core/provenance';
import { parsePackageSpec } from '../utils/registry';

export async function runVerify(
  options: VerifyCommandOptions,
  _config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const parsed = parsePackageSpec(options.packageSpec);
  const result = await verifyPackageProvenance(parsed.name, parsed.version, { rootDir });

  if (options.output) {
    fs.writeFileSync(path.resolve(rootDir, options.output), `${JSON.stringify(result, null, 2)}\n`);
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResult(result);
  }

  return options.failFast && result.issues.some((issue) => severityToNumber(issue.severity) >= severityToNumber('high'))
    ? 1
    : 0;
}

function printResult(result: Awaited<ReturnType<typeof verifyPackageProvenance>>): void {
  console.log(`GuardRail verify ${result.packageName}@${result.version}`);
  console.log(`publish method: ${result.publishMethod}`);
  console.log(`publisher: ${result.publishedBy ?? 'unknown'}${result.publisherEmail ? ` <${result.publisherEmail}>` : ''}`);
  console.log(`trusted publisher: ${result.hasTrustedPublisher ? 'yes' : 'no'}`);
  console.log(`provenance: ${result.hasProvenance ? 'present' : 'missing'}`);
  console.log(`registry signatures: ${result.hasRegistrySignatures ? 'present' : 'missing'}`);
  console.log(`sigstore/npm audit status: ${result.sigstoreStatus}`);
  console.log(`minimum observed SLSA build level: ${result.slsaBuildLevel}`);
  console.log(`integrity status: ${result.integrityStatus}`);

  if (result.sourceComparison) {
    console.log(`source overlap: ${String(result.sourceComparison.overlapCount)}`);
    console.log(`source match ratio: ${result.sourceComparison.matchRatio.toFixed(2)}`);
    console.log(`only in package: ${result.sourceComparison.onlyInPackage.slice(0, 15).join(', ') || 'none'}`);
    console.log(`modified in package: ${result.sourceComparison.modifiedInPackage.slice(0, 15).join(', ') || 'none'}`);
  }

  if (result.notes.length > 0) {
    console.log('notes:');
    for (const note of result.notes) {
      console.log(`- ${note}`);
    }
  }

  if (result.issues.length > 0) {
    console.log('issues:');
    for (const issue of result.issues) {
      console.log(`- [${issue.severity}] ${issue.code}: ${issue.title}`);
      console.log(`  ${issue.description}`);
      if (issue.recommendation) {
        console.log(`  action: ${issue.recommendation}`);
      }
    }
  }
}
```

## 9. src/commands/incident.ts
```ts
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
```

## 10. src/core/baseline.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import {
  BaselineFile,
  BaselineSnapshot,
  GuardrailConfig,
  PackageSnapshot,
  Severity,
} from '../types';

const BASELINE_FORMAT_VERSION = 1;

export function stripJsonComments(input: string): string {
  let output = '';
  let inString = false;
  let stringChar = '';
  let escaped = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let index = 0; index < input.length; index += 1) {
    const current = input[index] ?? '';
    const next = input[index + 1] ?? '';

    if (inLineComment) {
      if (current === '\n') {
        inLineComment = false;
        output += current;
      }
      continue;
    }

    if (inBlockComment) {
      if (current === '*' && next === '/') {
        inBlockComment = false;
        index += 1;
      }
      continue;
    }

    if (inString) {
      output += current;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (current === '\\') {
        escaped = true;
        continue;
      }
      if (current === stringChar) {
        inString = false;
        stringChar = '';
      }
      continue;
    }

    if ((current === '"' || current === "'") && !inString) {
      inString = true;
      stringChar = current;
      output += current;
      continue;
    }

    if (current === '/' && next === '/') {
      inLineComment = true;
      index += 1;
      continue;
    }

    if (current === '/' && next === '*') {
      inBlockComment = true;
      index += 1;
      continue;
    }

    output += current;
  }

  return output;
}

export function parseJsonc<T>(input: string): T {
  return JSON.parse(stripJsonComments(input)) as T;
}

export function readJsoncFile<T>(filePath: string): T {
  return parseJsonc<T>(fs.readFileSync(filePath, 'utf8'));
}

export function ensureDirectory(directoryPath: string): void {
  fs.mkdirSync(directoryPath, { recursive: true });
}

export function sha256(input: string | Uint8Array): string {
  const hash = crypto.createHash('sha256');
  hash.update(input);
  return hash.digest('hex');
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortValue(entry));
  }

  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      if (typeof record[key] === 'undefined') {
        continue;
      }
      result[key] = sortValue(record[key]);
    }
    return result;
  }

  return value;
}

export function compareSemverLoose(left: string, right: string): number {
  const leftParts = normalizeSemver(left);
  const rightParts = normalizeSemver(right);
  const length = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index] ?? '';
    const rightPart = rightParts[index] ?? '';
    const leftNumber = Number.parseInt(leftPart, 10);
    const rightNumber = Number.parseInt(rightPart, 10);
    const leftNumeric = Number.isFinite(leftNumber) && /^\d+$/.test(leftPart);
    const rightNumeric = Number.isFinite(rightNumber) && /^\d+$/.test(rightPart);

    if (leftNumeric && rightNumeric) {
      if (leftNumber !== rightNumber) {
        return leftNumber - rightNumber;
      }
      continue;
    }

    if (leftPart !== rightPart) {
      return leftPart.localeCompare(rightPart);
    }
  }

  return 0;
}

function normalizeSemver(input: string): string[] {
  return input
    .replace(/^v/i, '')
    .split(/[.+\-]/)
    .filter((part) => part.length > 0);
}

export function severityToNumber(severity: Severity): number {
  switch (severity) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    case 'info':
    default:
      return 1;
  }
}

export function numberToSeverity(value: number): Severity {
  if (value >= 5) {
    return 'critical';
  }
  if (value >= 4) {
    return 'high';
  }
  if (value >= 3) {
    return 'medium';
  }
  if (value >= 2) {
    return 'low';
  }
  return 'info';
}

export function redactSecret(value: string): string {
  if (value.length <= 8) {
    return '***';
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

export function getBaselinePaths(rootDir: string, config: GuardrailConfig): {
  baselineDir: string;
  baselinePath: string;
  privateKeyPath: string;
  publicKeyPath: string;
} {
  const baselineDir = config.baseline?.directory
    ? path.resolve(rootDir, config.baseline.directory)
    : path.join(rootDir, '.guardrail');

  return {
    baselineDir,
    baselinePath: config.baseline?.path
      ? path.resolve(rootDir, config.baseline.path)
      : path.join(baselineDir, 'baseline.json'),
    privateKeyPath: config.baseline?.privateKeyPath
      ? path.resolve(rootDir, config.baseline.privateKeyPath)
      : path.join(baselineDir, 'baseline-private.pem'),
    publicKeyPath: config.baseline?.publicKeyPath
      ? path.resolve(rootDir, config.baseline.publicKeyPath)
      : path.join(baselineDir, 'baseline-public.pem'),
  };
}

export function loadOrCreateKeyPair(rootDir: string, config: GuardrailConfig): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  const paths = getBaselinePaths(rootDir, config);
  ensureDirectory(paths.baselineDir);

  if (fs.existsSync(paths.privateKeyPath) && fs.existsSync(paths.publicKeyPath)) {
    return {
      privateKeyPem: fs.readFileSync(paths.privateKeyPath, 'utf8'),
      publicKeyPem: fs.readFileSync(paths.publicKeyPath, 'utf8'),
    };
  }

  const pair = crypto.generateKeyPairSync('ed25519');
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();

  fs.writeFileSync(paths.privateKeyPath, privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(paths.publicKeyPath, publicKeyPem, { mode: 0o644 });

  return { privateKeyPem, publicKeyPem };
}

export function signSnapshot(snapshot: BaselineSnapshot, privateKeyPem: string): string {
  const payload = Buffer.from(canonicalize(snapshot));
  const signature = crypto.sign(null, payload, privateKeyPem);
  return signature.toString('base64');
}

export function verifyBaselineSignature(file: BaselineFile): boolean {
  const payload = Buffer.from(canonicalize(file.snapshot));
  return crypto.verify(null, payload, file.publicKeyPem, Buffer.from(file.signature, 'base64'));
}

export function loadBaseline(rootDir: string, config: GuardrailConfig): {
  baseline: BaselineFile | null;
  path: string;
  verified: boolean;
} {
  const paths = getBaselinePaths(rootDir, config);
  if (!fs.existsSync(paths.baselinePath)) {
    return { baseline: null, path: paths.baselinePath, verified: false };
  }

  const baseline = JSON.parse(fs.readFileSync(paths.baselinePath, 'utf8')) as BaselineFile;
  if (baseline.formatVersion !== BASELINE_FORMAT_VERSION) {
    throw new Error(
      `Unsupported baseline format ${baseline.formatVersion}. Expected ${BASELINE_FORMAT_VERSION}.`,
    );
  }

  const verified = verifyBaselineSignature(baseline);
  if (!verified) {
    throw new Error(`Baseline signature verification failed for ${paths.baselinePath}`);
  }

  return { baseline, path: paths.baselinePath, verified };
}

export function writeBaseline(
  rootDir: string,
  config: GuardrailConfig,
  snapshot: BaselineSnapshot,
  previous?: BaselineFile | null,
): BaselineFile {
  const paths = getBaselinePaths(rootDir, config);
  const keys = loadOrCreateKeyPair(rootDir, config);
  ensureDirectory(paths.baselineDir);

  const now = new Date().toISOString();
  const baseline: BaselineFile = {
    formatVersion: BASELINE_FORMAT_VERSION,
    createdAt: previous?.createdAt ?? now,
    updatedAt: now,
    publicKeyPem: keys.publicKeyPem,
    signatureAlgorithm: 'ed25519',
    snapshot,
    signature: signSnapshot(snapshot, keys.privateKeyPem),
  };

  fs.writeFileSync(paths.baselinePath, `${JSON.stringify(baseline, null, 2)}\n`);
  return baseline;
}

export function snapshotKey(name: string, version: string): string {
  return `${name}@${version}`;
}

export function latestSnapshotForPackage(
  snapshot: BaselineSnapshot,
  packageName: string,
): PackageSnapshot | undefined {
  const matches = Object.values(snapshot.packages).filter((entry) => entry.name === packageName);
  if (matches.length === 0) {
    return undefined;
  }

  return matches.sort((left, right) => compareSemverLoose(right.version, left.version))[0];
}

export function mergeSnapshots(
  existing: BaselineSnapshot | undefined,
  packages: Record<string, PackageSnapshot>,
  rootManifestHash: string,
  lockfileHash: string | undefined,
  packageManager: BaselineSnapshot['packageManager'],
): BaselineSnapshot {
  return {
    generatedAt: new Date().toISOString(),
    rootManifestHash,
    lockfileHash,
    packageManager,
    packages: {
      ...(existing?.packages ?? {}),
      ...packages,
    },
  };
}
```

## 11. src/core/script-analyzer.ts
```ts
import { ScriptFinding, Severity } from '../types';
import { numberToSeverity, sha256 } from './baseline';

interface Rule {
  id: string;
  weight: number;
  reason: string;
  patterns: RegExp[];
}

const RULES: Rule[] = [
  {
    id: 'network',
    weight: 20,
    reason: 'network activity in install script',
    patterns: [
      /\bcurl\b/i,
      /\bwget\b/i,
      /https?:\/\//i,
      /\bInvoke-WebRequest\b/i,
      /\bStart-BitsTransfer\b/i,
      /\bfetch\s*\(/i,
      /\bXMLHttpRequest\b/i,
      /\bnc\b/i,
      /\bscp\b/i,
    ],
  },
  {
    id: 'process-spawn',
    weight: 16,
    reason: 'process spawning or shell execution',
    patterns: [
      /\b(child_process|spawn|exec|execFile|fork)\b/i,
      /\bpowershell(?:\.exe)?\b/i,
      /\bcmd(?:\.exe)?\b/i,
      /\bbash\b/i,
      /\bsh\s+-c\b/i,
      /\bosascript\b/i,
      /\bpython3?\b/i,
      /\bnode\s+[^\n]+\.[cm]?[jt]s\b/i,
    ],
  },
  {
    id: 'eval',
    weight: 18,
    reason: 'dynamic code execution or decoding',
    patterns: [
      /\beval\s*\(/i,
      /\bnew Function\b/i,
      /\bvm\./i,
      /\batob\s*\(/i,
      /Buffer\.from\([^\)]*base64/i,
      /fromCharCode\s*\(/i,
    ],
  },
  {
    id: 'file-system',
    weight: 12,
    reason: 'filesystem mutation in install script',
    patterns: [
      /\b(writeFile|appendFile|copyFile|renameSync|rename|unlinkSync|unlink|rmSync|rm\s+-rf|Move-Item|Copy-Item|Set-Content|Out-File)\b/i,
      /\/Library\/Caches\//i,
      /%PROGRAMDATA%/i,
      /\\ProgramData\\/i,
      /\/tmp\//i,
      />\s*[^\n]+/i,
    ],
  },
  {
    id: 'persistence',
    weight: 15,
    reason: 'persistence or startup path references',
    patterns: [
      /launchctl/i,
      /schtasks/i,
      /RunOnce/i,
      /Startup/i,
      /crontab/i,
      /systemctl/i,
      /registry\.set/i,
      /HKEY_/i,
    ],
  },
  {
    id: 'anti-forensics',
    weight: 18,
    reason: 'self-delete, package tampering, or anti-forensic behavior',
    patterns: [
      /\b(self\-delete|selfdestruct|unlinkSync|unlink|rm\s+-f|del\s+\/f|erase\s+)\b/i,
      /package\.json/i,
      /npm list/i,
      /move\s+package/i,
      /rename\s+package/i,
    ],
  },
  {
    id: 'obfuscation',
    weight: 20,
    reason: 'encoded or obfuscated content',
    patterns: [
      /[A-Za-z0-9+/]{180,}={0,2}/,
      /(?:0x[0-9a-f]{2,}){20,}/i,
      /\bXOR\b/i,
      /\bcharCodeAt\s*\(/i,
      /\bString\.fromCharCode\s*\(/i,
      /\bdecodeURIComponent\s*\(/i,
    ],
  },
];

const LIFECYCLE_SCRIPT_NAMES = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
]);

export function pickLifecycleScripts(scripts: Record<string, string> | undefined): Record<string, string> {
  if (!scripts) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [name, command] of Object.entries(scripts)) {
    if (LIFECYCLE_SCRIPT_NAMES.has(name) && typeof command === 'string' && command.trim().length > 0) {
      result[name] = command.trim();
    }
  }
  return result;
}

export function hashLifecycleScripts(scripts: Record<string, string>): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const [name, command] of Object.entries(scripts)) {
    hashes[name] = sha256(command);
  }
  return hashes;
}

export function analyzeLifecycleScripts(
  packageName: string,
  packageVersion: string,
  scripts: Record<string, string>,
  resolveFileContent?: (relativePath: string) => string | undefined,
): ScriptFinding[] {
  const findings: ScriptFinding[] = [];

  for (const [scriptName, command] of Object.entries(scripts)) {
    const referencedFiles = extractLikelyScriptFiles(command);
    const supplementalEvidence: string[] = [];
    let expandedCommand = command;

    for (const file of referencedFiles) {
      const content = resolveFileContent?.(file);
      if (!content) {
        continue;
      }
      supplementalEvidence.push(`loaded ${file}`);
      expandedCommand += `\n${content}`;
    }

    const scoreResult = scoreScript(expandedCommand);
    findings.push({
      packageName,
      packageVersion,
      scriptName,
      command,
      score: scoreResult.score,
      severity: scoreResult.severity,
      reasons: scoreResult.reasons,
      evidence: [...supplementalEvidence, ...scoreResult.evidence],
    });
  }

  return findings;
}

export function highestScriptRisk(findings: ScriptFinding[]): number {
  return findings.reduce((highest, finding) => Math.max(highest, finding.score), 0);
}

function scoreScript(text: string): {
  score: number;
  severity: Severity;
  reasons: string[];
  evidence: string[];
} {
  let score = 0;
  const reasons: string[] = [];
  const evidence: string[] = [];

  for (const rule of RULES) {
    const matched = rule.patterns.some((pattern) => pattern.test(text));
    if (!matched) {
      continue;
    }
    score += rule.weight;
    reasons.push(rule.reason);
    evidence.push(rule.id);
  }

  const suspiciousLengthBonus = calculateSuspiciousLengthBonus(text);
  if (suspiciousLengthBonus > 0) {
    score += suspiciousLengthBonus;
    reasons.push('very long command or embedded payload');
    evidence.push('long-payload');
  }

  const repeatedEncodingBonus = calculateRepeatedEncodingBonus(text);
  if (repeatedEncodingBonus > 0) {
    score += repeatedEncodingBonus;
    reasons.push('multiple encoded or escaped fragments');
    evidence.push('repeated-encoding');
  }

  score = Math.min(score, 100);
  return {
    score,
    severity: numberToSeverity(scoreToSeverityRank(score)),
    reasons,
    evidence,
  };
}

function scoreToSeverityRank(score: number): number {
  if (score >= 85) {
    return 5;
  }
  if (score >= 70) {
    return 4;
  }
  if (score >= 45) {
    return 3;
  }
  if (score >= 20) {
    return 2;
  }
  return 1;
}

function calculateSuspiciousLengthBonus(text: string): number {
  const compact = text.replace(/\s+/g, '');
  if (compact.length >= 5000) {
    return 12;
  }
  if (compact.length >= 2000) {
    return 8;
  }
  if (compact.length >= 800) {
    return 4;
  }
  return 0;
}

function calculateRepeatedEncodingBonus(text: string): number {
  const base64Matches = text.match(/[A-Za-z0-9+/]{60,}={0,2}/g) ?? [];
  const escapedMatches = text.match(/\\x[0-9a-f]{2}/gi) ?? [];
  if (base64Matches.length >= 3 || escapedMatches.length >= 10) {
    return 10;
  }
  if (base64Matches.length >= 1 || escapedMatches.length >= 5) {
    return 5;
  }
  return 0;
}

export function extractLikelyScriptFiles(command: string): string[] {
  const files = new Set<string>();
  const patterns = [
    /\bnode\s+(?:--require\s+[^\s]+\s+)?([./A-Za-z0-9_\-\\/]+\.[cm]?[jt]s)\b/g,
    /\b(?:bash|sh|zsh)\s+([./A-Za-z0-9_\-\\/]+\.sh)\b/g,
    /\b(?:python|python3)\s+([./A-Za-z0-9_\-\\/]+\.py)\b/g,
    /\b(?:powershell|pwsh)(?:\.exe)?\s+(?:-File\s+)?([./A-Za-z0-9_\-\\/]+\.ps1)\b/g,
    /\b([./A-Za-z0-9_\-\\/]+\.(?:js|cjs|mjs|ts|sh|py|ps1))\b/g,
  ];

  for (const pattern of patterns) {
    let match: RegExpExecArray | null = pattern.exec(command);
    while (match) {
      const candidate = normalizeRelativePath(match[1] ?? '');
      if (candidate.length > 0 && !candidate.startsWith('http')) {
        files.add(candidate);
      }
      match = pattern.exec(command);
    }
  }

  return Array.from(files);
}

function normalizeRelativePath(input: string): string {
  return input.replace(/^['"`]/, '').replace(/['"`]$/, '').replace(/^\.\//, '');
}
```

## 12. src/core/npm-feed.ts
```ts
import { FeedChange } from '../types';
import { fetchJson } from '../utils/registry';

interface ChangeFeedResponse {
  last_seq: number;
  results: Array<{
    seq: number;
    id: string;
    deleted?: boolean;
    doc?: Record<string, unknown>;
  }>;
}

export class NpmFeedSubscriber {
  private readonly changesUrl: string;

  public constructor(private readonly timeoutMs = 25000) {
    this.changesUrl = 'https://replicate.npmjs.com/_changes';
  }

  public async fetchLatestSequence(): Promise<number> {
    const response = await fetchJson<ChangeFeedResponse>(
      `${this.changesUrl}?descending=true&limit=1`,
      { timeoutMs: 10000 },
    );

    if (typeof response.last_seq === 'number') {
      return response.last_seq;
    }

    if (response.results.length > 0) {
      return response.results[0]?.seq ?? 0;
    }

    return 0;
  }

  public async pollOnce(since: number): Promise<{ lastSeq: number; changes: FeedChange[] }> {
    const url = `${this.changesUrl}?include_docs=true&since=${since}&feed=longpoll&timeout=${this.timeoutMs}&limit=100`;
    const response = await fetchJson<ChangeFeedResponse>(url, {
      timeoutMs: this.timeoutMs + 5000,
    });

    return {
      lastSeq: typeof response.last_seq === 'number' ? response.last_seq : since,
      changes: response.results.map((entry) => ({
        sequence: entry.seq,
        packageName: entry.id,
        deleted: entry.deleted,
        doc: entry.doc,
      })),
    };
  }

  public async watch(
    packageNames: Set<string>,
    onChange: (change: FeedChange) => Promise<void>,
    options: {
      startAt?: number;
      once?: boolean;
    } = {},
  ): Promise<void> {
    let since = typeof options.startAt === 'number' ? options.startAt : await this.fetchLatestSequence();

    while (true) {
      const result = await this.pollOnce(since);
      since = result.lastSeq;

      for (const change of result.changes) {
        if (!packageNames.has(change.packageName)) {
          continue;
        }
        await onChange(change);
      }

      if (options.once) {
        return;
      }
    }
  }
}
```

## 13. src/core/provenance.ts
```ts
import * as childProcess from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

import {
  IntegrityDiff,
  PackageSnapshot,
  PublishMethod,
  RegistryPackageVersionMetadata,
  RemotePackageAnalysis,
  ScanIssue,
  VerificationResult,
} from '../types';
import { latestSnapshotForPackage, numberToSeverity, severityToNumber, sha256 } from './baseline';
import {
  analyzeLifecycleScripts,
  hashLifecycleScripts,
  highestScriptRisk,
  pickLifecycleScripts,
} from './script-analyzer';
import {
  downloadBuffer,
  fetchPackageVersion,
  recursiveFindKey,
  toRecord,
} from '../utils/registry';

const SOURCE_FILE_PATTERN = /\.(?:[cm]?[jt]sx?|json)$/i;
const IGNORED_SOURCE_PATHS = [/^package\/node_modules\//, /^package\/test\//, /^package\/tests\//, /^package\/docs?\//];

export async function analyzeRegistryPackage(
  packageName: string,
  version?: string,
): Promise<RemotePackageAnalysis> {
  const metadata = await fetchPackageVersion(packageName, version);
  const tarballUrl = metadata.dist?.tarball;
  if (!tarballUrl) {
    throw new Error(`No tarball URL was published for ${metadata.name}@${metadata.version}`);
  }

  const tarball = await downloadBuffer(tarballUrl, { timeoutMs: 30000 });
  const files = extractTarGzEntries(tarball);
  const packageJsonPath = findPackageJsonPath(files);
  if (!packageJsonPath) {
    throw new Error(`No package.json was found in the tarball for ${metadata.name}@${metadata.version}`);
  }

  const packageJsonBuffer = files[packageJsonPath];
  if (!packageJsonBuffer) {
    throw new Error(`package.json path resolved but file content was missing for ${metadata.name}@${metadata.version}`);
  }
  const packageJson = JSON.parse(decodeUtf8(packageJsonBuffer));
  const snapshot = buildSnapshotFromTarball(metadata, packageJson, files);
  return {
    metadata,
    snapshot,
    tarballSha256: sha256(tarball),
    files,
  };
}

export function inferPublishMethod(metadata: RegistryPackageVersionMetadata): PublishMethod {
  const trustedPublisher = recursiveFindKey(metadata, 'trustedPublisher');
  if (trustedPublisher) {
    return 'trusted-publishing';
  }
  if (metadata._npmUser?.name) {
    return 'manual-or-token';
  }
  return 'unknown';
}

export function hasProvenanceSignal(metadata: RegistryPackageVersionMetadata): boolean {
  return Boolean(
    recursiveFindKey(metadata, 'provenance') ||
      recursiveFindKey(metadata, 'attestation') ||
      recursiveFindKey(metadata, 'predicateType'),
  );
}

export function hasRegistrySignatureSignal(metadata: RegistryPackageVersionMetadata): boolean {
  if (metadata.dist?.signatures) {
    return true;
  }
  return Boolean(recursiveFindKey(metadata, 'npm-signature') || recursiveFindKey(metadata, 'signatures'));
}

export async function verifyPackageProvenance(
  packageName: string,
  version?: string,
  options: {
    rootDir?: string;
  } = {},
): Promise<VerificationResult> {
  const analysis = await analyzeRegistryPackage(packageName, version);
  const metadata = analysis.metadata;
  const publishMethod = inferPublishMethod(metadata);
  const hasTrustedPublisher = publishMethod === 'trusted-publishing';
  let hasProvenance = hasProvenanceSignal(metadata);
  let sigstoreStatus: VerificationResult['sigstoreStatus'] = hasRegistrySignatureSignal(metadata)
    ? 'present-unverified'
    : 'not-found';
  const notes: string[] = [];
  const issues: ScanIssue[] = [];

  const audit = runNpmAuditSignatures(metadata.name, metadata.version);
  if (audit.verified) {
    sigstoreStatus = 'verified';
    hasProvenance = hasProvenance || audit.provenanceVerified;
    notes.push('npm audit signatures verified registry signatures or provenance attestations.');
  } else if (audit.error) {
    notes.push(`npm audit signatures was unavailable: ${audit.error}`);
  }

  const sourceComparison = await compareToGitHubSource(metadata, analysis.files);
  let integrityStatus: VerificationResult['integrityStatus'] = 'not-checked';
  if (sourceComparison) {
    if (sourceComparison.modifiedInPackage.length === 0 && sourceComparison.onlyInPackage.length === 0) {
      integrityStatus = 'verified';
    } else if (sourceComparison.modifiedInPackage.length === 0 && sourceComparison.overlapCount > 0) {
      integrityStatus = 'partial';
    } else {
      integrityStatus = 'mismatch';
    }
  } else {
    notes.push('Repository source comparison was skipped because repository metadata was incomplete or non-GitHub.');
  }

  const inconsistentProvenanceSignal = await detectPeerProvenanceInconsistency(
    options.rootDir,
    metadata.name,
    hasTrustedPublisher || hasProvenance,
  );

  if (publishMethod === 'manual-or-token' && !hasTrustedPublisher) {
    issues.push({
      id: `${metadata.name}@${metadata.version}:publish-method`,
      code: 'GR_PUBLISH_PATH',
      category: 'provenance',
      severity: 'high',
      title: 'Package was not published through trusted publishing',
      description:
        'Registry metadata did not expose a trusted publisher signal. This release appears to have used a direct manual or token-based publish path.',
      packageName: metadata.name,
      packageVersion: metadata.version,
      recommendation:
        'Require OIDC trusted publishing and disallow traditional tokens for this package. Treat unexpected manual publishes as an incident until proven otherwise.',
    });
  }

  if (!hasProvenance) {
    issues.push({
      id: `${metadata.name}@${metadata.version}:provenance-missing`,
      code: 'GR_PROVENANCE_MISSING',
      category: 'provenance',
      severity: inconsistentProvenanceSignal ? 'high' : 'medium',
      title: 'No provenance attestation signal was found',
      description:
        'This package version did not expose a provenance attestation signal through registry metadata or npm audit signatures.',
      packageName: metadata.name,
      packageVersion: metadata.version,
      recommendation:
        'Prefer package versions published through trusted publishing with provenance. Treat missing provenance as a stronger signal when peer packages in the same project do have it.',
    });
  }

  if (integrityStatus === 'mismatch') {
    issues.push({
      id: `${metadata.name}@${metadata.version}:source-mismatch`,
      code: 'GR_SOURCE_MISMATCH',
      category: 'integrity',
      severity: 'high',
      title: 'Published tarball differs from tagged source',
      description:
        'Overlapping files in the npm tarball and the GitHub source archive had content mismatches.',
      packageName: metadata.name,
      packageVersion: metadata.version,
      evidence: sourceComparison
        ? [
            `modified files: ${sourceComparison.modifiedInPackage.slice(0, 10).join(', ') || 'none'}`,
            `overlap count: ${String(sourceComparison.overlapCount)}`,
          ]
        : undefined,
      recommendation:
        'Investigate whether the package was built from a different commit, tampered after build, or published through an unauthorized path.',
    });
  }

  if (inconsistentProvenanceSignal) {
    issues.push({
      id: `${metadata.name}@${metadata.version}:peer-provenance`,
      code: 'GR_PROVENANCE_INCONSISTENT',
      category: 'provenance',
      severity: 'medium',
      title: 'Provenance is missing where peer packages have it',
      description:
        'Other direct dependencies in this project expose provenance or trusted publishing signals, but this package version does not.',
      packageName: metadata.name,
      packageVersion: metadata.version,
      recommendation:
        'Use provenance consistency as a policy gate. Sudden regression from attested to unattested releases deserves immediate review.',
    });
  }

  return {
    packageName: metadata.name,
    version: metadata.version,
    publishMethod,
    publishedBy: metadata._npmUser?.name,
    publisherEmail: metadata._npmUser?.email,
    hasTrustedPublisher,
    hasProvenance,
    hasRegistrySignatures: hasRegistrySignatureSignal(metadata),
    slsaBuildLevel: hasTrustedPublisher && hasProvenance ? '2' : 'unknown',
    sigstoreStatus,
    integrityStatus,
    sourceComparison: sourceComparison ?? undefined,
    inconsistentProvenanceSignal,
    notes,
    issues: issues.sort((left, right) => severityToNumber(right.severity) - severityToNumber(left.severity)),
    metadata: {
      repository: metadata.repository ?? null,
      gitHead: metadata.gitHead ?? null,
      dist: metadata.dist ?? null,
      trustedPublisher: recursiveFindKey(metadata, 'trustedPublisher') ?? null,
    },
  };
}

function buildSnapshotFromTarball(
  metadata: RegistryPackageVersionMetadata,
  packageJson: Record<string, unknown>,
  files: Record<string, Uint8Array>,
): PackageSnapshot {
  const declaredDependencies = Object.keys(normalizeDependencyRecord(packageJson.dependencies)).sort();
  const optionalDependencies = Object.keys(normalizeDependencyRecord(packageJson.optionalDependencies)).sort();
  const peerDependencies = Object.keys(normalizeDependencyRecord(packageJson.peerDependencies)).sort();
  const lifecycleScripts = pickLifecycleScripts(normalizeScriptRecord(packageJson.scripts));
  const importedDependencies = Array.from(scanImports(files)).sort();
  const unusedDeclaredDependencies = declaredDependencies.filter(
    (dependency) => !importedDependencies.includes(dependency),
  );
  const scriptFindings = analyzeLifecycleScripts(
    metadata.name,
    metadata.version,
    lifecycleScripts,
    (relativePath) => resolvePackageTextFile(files, relativePath),
  );

  const relevantFileHashes = Object.entries(files)
    .filter(([name]) => SOURCE_FILE_PATTERN.test(name) && !IGNORED_SOURCE_PATHS.some((pattern) => pattern.test(name)))
    .map(([name, content]) => `${name}:${sha256(content)}`)
    .sort();

  const manifestString = JSON.stringify(packageJson);
  const sourceHash = sha256(relevantFileHashes.join('\n'));
  const manifestHash = sha256(manifestString);

  return {
    name: metadata.name,
    version: metadata.version,
    declaredDependencies,
    optionalDependencies,
    peerDependencies,
    importedDependencies,
    unusedDeclaredDependencies,
    lifecycleScripts,
    lifecycleScriptHashes: hashLifecycleScripts(lifecycleScripts),
    scriptFindings,
    highestScriptRisk: highestScriptRisk(scriptFindings),
    sourceFileCount: relevantFileHashes.length,
    manifestHash,
    sourceHash,
    packageHash: sha256([manifestHash, sourceHash, JSON.stringify(lifecycleScripts)].join(':')),
    registry: {
      gitHead: metadata.gitHead,
      repository: metadata.repository,
      _npmUser: metadata._npmUser,
      trustedPublisher: recursiveFindKey(metadata, 'trustedPublisher'),
    },
  };
}

function normalizeDependencyRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawVersion] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawVersion === 'string') {
      result[name] = rawVersion;
    }
  }
  return result;
}

function normalizeScriptRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawCommand] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawCommand === 'string') {
      result[name] = rawCommand;
    }
  }
  return result;
}

function scanImports(files: Record<string, Uint8Array>): Set<string> {
  const imports = new Set<string>();
  for (const [name, content] of Object.entries(files)) {
    if (!SOURCE_FILE_PATTERN.test(name) || IGNORED_SOURCE_PATHS.some((pattern) => pattern.test(name))) {
      continue;
    }

    const text = decodeUtf8(content);
    for (const specifier of extractModuleSpecifiers(text)) {
      const packageName = normalizeModuleSpecifier(specifier);
      if (packageName) {
        imports.add(packageName);
      }
    }
  }
  return imports;
}

function extractModuleSpecifiers(source: string): string[] {
  const patterns = [
    /import\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
    /import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /export\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
  ];

  const result: string[] = [];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null = pattern.exec(source);
    while (match) {
      if (match[1]) {
        result.push(match[1]);
      }
      match = pattern.exec(source);
    }
  }
  return result;
}

function normalizeModuleSpecifier(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {
    return undefined;
  }
  const segments = specifier.split('/').filter(Boolean);
  if (segments.length === 0) {
    return undefined;
  }
  if (segments[0]?.startsWith('@') && segments[1]) {
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0];
}

function resolvePackageTextFile(files: Record<string, Uint8Array>, relativePath: string): string | undefined {
  const candidates = [
    relativePath.replace(/^\.\//, ''),
    `package/${relativePath.replace(/^\.\//, '')}`,
  ];

  for (const candidate of candidates) {
    const buffer = files[candidate];
    if (!buffer) {
      continue;
    }
    return decodeUtf8(buffer);
  }
  return undefined;
}

function findPackageJsonPath(files: Record<string, Uint8Array>): string | undefined {
  return Object.keys(files).find((name) => name === 'package/package.json' || name.endsWith('/package.json'));
}

function decodeUtf8(input: Uint8Array): string {
  return Buffer.from(input).toString('utf8');
}

export function extractTarGzEntries(buffer: Uint8Array): Record<string, Uint8Array> {
  const gzipBuffer = Buffer.from(buffer);
  const tarBuffer = zlib.gunzipSync(gzipBuffer);
  const entries: Record<string, Uint8Array> = {};
  let offset = 0;
  let pendingPaxHeaders: Record<string, string> = {};

  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      break;
    }

    const name = readTarString(header.subarray(0, 100));
    const size = parseTarOctal(header.subarray(124, 136));
    const typeFlag = readTarString(header.subarray(156, 157)) || '0';
    const prefix = readTarString(header.subarray(345, 500));
    const basePath = prefix ? `${prefix}/${name}` : name;
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const payload = tarBuffer.subarray(dataStart, dataEnd);
    const roundedSize = Math.ceil(size / 512) * 512;

    if (typeFlag === 'x') {
      pendingPaxHeaders = parsePaxHeaders(payload);
    } else if (typeFlag !== '5') {
      const entryName = pendingPaxHeaders.path || basePath;
      entries[entryName] = new Uint8Array(payload);
      pendingPaxHeaders = {};
    }

    offset = dataStart + roundedSize;
  }

  return entries;
}

function isZeroBlock(buffer: Uint8Array): boolean {
  for (const byte of buffer) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

function readTarString(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString('utf8').replace(/\0.*$/, '').trim();
}

function parseTarOctal(buffer: Uint8Array): number {
  const value = readTarString(buffer).replace(/[^0-7]/g, '').trim();
  return value ? Number.parseInt(value, 8) : 0;
}

function parsePaxHeaders(buffer: Uint8Array): Record<string, string> {
  const text = decodeUtf8(buffer);
  const headers: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const separator = line.indexOf(' ');
    if (separator === -1) {
      continue;
    }
    const record = line.slice(separator + 1);
    const equalsIndex = record.indexOf('=');
    if (equalsIndex === -1) {
      continue;
    }
    const key = record.slice(0, equalsIndex);
    const value = record.slice(equalsIndex + 1);
    headers[key] = value;
  }
  return headers;
}

async function compareToGitHubSource(
  metadata: RegistryPackageVersionMetadata,
  npmFiles: Record<string, Uint8Array>,
): Promise<IntegrityDiff | null> {
  const repository = normalizeGitHubRepository(metadata.repository);
  if (!repository || !metadata.gitHead) {
    return null;
  }

  const sourceUrl = `https://codeload.github.com/${repository.owner}/${repository.repo}/tar.gz/${metadata.gitHead}`;
  const sourceTarball = await downloadBuffer(sourceUrl, { timeoutMs: 30000 });
  const sourceFilesRaw = extractTarGzEntries(sourceTarball);
  const sourceFiles = stripFirstPathSegment(sourceFilesRaw);
  const packageFiles = normalizePackageTarballPaths(npmFiles);

  const onlyInPackage: string[] = [];
  const modifiedInPackage: string[] = [];
  let matched = 0;

  for (const [filePath, content] of Object.entries(packageFiles)) {
    if (shouldIgnoreSourceComparisonPath(filePath)) {
      continue;
    }
    const source = sourceFiles[filePath];
    if (!source) {
      onlyInPackage.push(filePath);
      continue;
    }

    if (sha256(content) !== sha256(source)) {
      modifiedInPackage.push(filePath);
    } else {
      matched += 1;
    }
  }

  const overlapCount = matched + modifiedInPackage.length;
  return {
    onlyInPackage: onlyInPackage.sort(),
    modifiedInPackage: modifiedInPackage.sort(),
    overlapCount,
    matchRatio: overlapCount > 0 ? matched / overlapCount : 0,
  };
}

function normalizePackageTarballPaths(files: Record<string, Uint8Array>): Record<string, Uint8Array> {
  const normalized: Record<string, Uint8Array> = {};
  for (const [name, content] of Object.entries(files)) {
    const stripped = name.startsWith('package/') ? name.slice('package/'.length) : name;
    normalized[stripped] = content;
  }
  return normalized;
}

function stripFirstPathSegment(files: Record<string, Uint8Array>): Record<string, Uint8Array> {
  const stripped: Record<string, Uint8Array> = {};
  for (const [name, content] of Object.entries(files)) {
    const separator = name.indexOf('/');
    if (separator === -1) {
      continue;
    }
    stripped[name.slice(separator + 1)] = content;
  }
  return stripped;
}

function shouldIgnoreSourceComparisonPath(filePath: string): boolean {
  return (
    filePath.length === 0 ||
    /^\.github\//.test(filePath) ||
    /^docs?\//.test(filePath) ||
    /^examples?\//.test(filePath) ||
    /^tests?\//.test(filePath)
  );
}

function normalizeGitHubRepository(
  repository: RegistryPackageVersionMetadata['repository'],
): { owner: string; repo: string } | null {
  const repositoryUrl = typeof repository === 'string' ? repository : repository?.url;
  if (!repositoryUrl) {
    return null;
  }

  const normalized = repositoryUrl
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '');

  const match = normalized.match(/github\.com[/:]([^/]+)\/([^/]+)/i);
  if (!match?.[1] || !match[2]) {
    return null;
  }

  return {
    owner: match[1],
    repo: match[2],
  };
}

function runNpmAuditSignatures(
  packageName: string,
  version: string,
): { verified: boolean; provenanceVerified: boolean; error?: string } {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'guardrail-audit-'));

  try {
    fs.writeFileSync(
      path.join(tempRoot, 'package.json'),
      JSON.stringify(
        {
          private: true,
          name: 'guardrail-temp-audit',
          version: '0.0.0',
          dependencies: {
            [packageName]: version,
          },
        },
        null,
        2,
      ),
    );

    const install = childProcess.spawnSync('npm', ['install', '--ignore-scripts', '--silent'], {
      cwd: tempRoot,
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });

    if (install.status !== 0) {
      return {
        verified: false,
        provenanceVerified: false,
        error: install.stderr?.trim() || install.stdout?.trim() || 'npm install failed',
      };
    }

    const audit = childProcess.spawnSync('npm', ['audit', 'signatures', '--json'], {
      cwd: tempRoot,
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });

    if (audit.status !== 0 && !audit.stdout) {
      return {
        verified: false,
        provenanceVerified: false,
        error: audit.stderr?.trim() || 'npm audit signatures failed',
      };
    }

    const output = `${audit.stdout ?? ''}\n${audit.stderr ?? ''}`;
    const lower = output.toLowerCase();
    return {
      verified: /(verified|signatures verified|provenance verified)/i.test(output),
      provenanceVerified: /provenance/i.test(lower) && /verified/i.test(lower),
      error: audit.status === 0 ? undefined : audit.stderr?.trim() || undefined,
    };
  } catch (error) {
    return {
      verified: false,
      provenanceVerified: false,
      error: formatError(error),
    };
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function detectPeerProvenanceInconsistency(
  rootDir: string | undefined,
  packageName: string,
  packageHasProvenance: boolean,
): Promise<boolean> {
  if (!rootDir || packageHasProvenance) {
    return false;
  }

  const rootPackageJson = path.join(rootDir, 'package.json');
  if (!fs.existsSync(rootPackageJson)) {
    return false;
  }

  const dependencies = collectInstalledDirectDependencies(rootDir);
  const peerNames = dependencies.filter((name) => name !== packageName).slice(0, 12);
  if (peerNames.length === 0) {
    return false;
  }

  for (const peerName of peerNames) {
    try {
      const peerPackageJson = path.join(rootDir, 'node_modules', peerName, 'package.json');
      if (!fs.existsSync(peerPackageJson)) {
        continue;
      }
      const installed = JSON.parse(fs.readFileSync(peerPackageJson, 'utf8')) as Record<string, unknown>;
      const version = typeof installed.version === 'string' ? installed.version : undefined;
      if (!version) {
        continue;
      }
      const metadata = await fetchPackageVersion(peerName, version);
      if (inferPublishMethod(metadata) === 'trusted-publishing' || hasProvenanceSignal(metadata)) {
        return true;
      }
    } catch {
      // Best-effort signal only.
    }
  }

  return false;
}

function collectInstalledDirectDependencies(rootDir: string): string[] {
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    return [];
  }
  const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as Record<string, unknown>;
  const deps = Object.keys(toRecord(parsed.dependencies));
  const optional = Object.keys(toRecord(parsed.optionalDependencies));
  return Array.from(new Set([...deps, ...optional])).sort();
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
```

## 14. src/core/token-scanner.ts
```ts
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
```

## 15. src/integrations/github-actions.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

import { WorkflowRunCandidate } from '../types';
import { downloadBuffer, fetchJson } from '../utils/registry';

interface GitHubRunSummary {
  id: number;
  name?: string;
  display_title?: string;
  html_url?: string;
  status?: string;
  conclusion?: string;
  created_at?: string;
  updated_at?: string;
}

interface GitHubRunsResponse {
  workflow_runs: GitHubRunSummary[];
}

export function generateGuardrailWorkflow(): string {
  return `name: guardrail
on:
  push:
    branches:
      - main
      - master
  pull_request:

jobs:
  guardrail:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
      id-token: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: npm

      - name: Install GuardRail
        run: npm install -g guardrail-security

      - name: Run GuardRail scan before dependency install
        run: guardrail scan --fail-fast --sarif guardrail.sarif

      - name: Install dependencies without lifecycle scripts
        run: npm ci --ignore-scripts

      - name: Upload GuardRail SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardrail.sarif
`;
}

export function collectWorkflowSecretReferences(rootDir: string): string[] {
  const workflowFiles = collectWorkflowFiles(rootDir);
  const secrets = new Set<string>();

  for (const filePath of workflowFiles) {
    const text = fs.readFileSync(filePath, 'utf8');
    const matches = text.match(/\$\{\{\s*secrets\.([A-Za-z0-9_\-]+)\s*\}\}/g) ?? [];
    for (const match of matches) {
      const name = match.match(/secrets\.([A-Za-z0-9_\-]+)/)?.[1];
      if (name) {
        secrets.add(name);
      }
    }
  }

  return Array.from(secrets).sort();
}

export async function listWorkflowRuns(
  owner: string,
  repo: string,
  from: string,
  to: string,
  token: string,
): Promise<GitHubRunSummary[]> {
  const created = `${from}..${to}`;
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs?per_page=100&created=${encodeURIComponent(created)}`;
  const response = await fetchJson<GitHubRunsResponse>(url, {
    timeoutMs: 20000,
    headers: githubHeaders(token),
  });
  return response.workflow_runs ?? [];
}

export async function scanWorkflowRunsForPackage(
  owner: string,
  repo: string,
  from: string,
  to: string,
  token: string,
  indicators: string[],
): Promise<WorkflowRunCandidate[]> {
  const runs = await listWorkflowRuns(owner, repo, from, to, token);
  const results: WorkflowRunCandidate[] = [];

  for (const run of runs) {
    const candidate = await scanSingleRun(owner, repo, run, token, indicators);
    results.push(candidate);
  }

  return results.sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
}

async function scanSingleRun(
  owner: string,
  repo: string,
  run: GitHubRunSummary,
  token: string,
  indicators: string[],
): Promise<WorkflowRunCandidate> {
  const base: WorkflowRunCandidate = {
    id: run.id,
    name: run.display_title || run.name || `run-${run.id}`,
    htmlUrl: run.html_url || `https://github.com/${owner}/${repo}/actions/runs/${run.id}`,
    status: run.status || 'unknown',
    conclusion: run.conclusion || undefined,
    createdAt: run.created_at || new Date(0).toISOString(),
    updatedAt: run.updated_at || new Date(0).toISOString(),
    possibleMatch: false,
    matches: [],
  };

  try {
    const logArchive = await downloadBuffer(
      `https://api.github.com/repos/${owner}/${repo}/actions/runs/${run.id}/logs`,
      {
        timeoutMs: 30000,
        headers: githubHeaders(token),
      },
    );

    const entries = extractZipEntries(logArchive);
    const normalizedIndicators = indicators.map((indicator) => indicator.toLowerCase()).filter(Boolean);

    for (const [fileName, content] of Object.entries(entries)) {
      const lower = content.toLowerCase();
      for (const indicator of normalizedIndicators) {
        if (!indicator || !lower.includes(indicator)) {
          continue;
        }
        base.possibleMatch = true;
        base.matches.push(`${indicator} in ${fileName}`);
      }

      if (/(npm|pnpm|yarn|bun)\s+(install|ci|add)/i.test(content)) {
        base.matches.push(`dependency install command in ${fileName}`);
      }
    }
  } catch (error) {
    base.matches.push(`log scan failed: ${formatError(error)}`);
  }

  base.matches = Array.from(new Set(base.matches)).sort();
  return base;
}

function githubHeaders(token: string): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'user-agent': 'guardrail-security',
    'x-github-api-version': '2022-11-28',
  };
}

function collectWorkflowFiles(rootDir: string): string[] {
  const files: string[] = [];
  const workflowDir = path.join(rootDir, '.github', 'workflows');
  if (fs.existsSync(workflowDir)) {
    for (const entry of fs.readdirSync(workflowDir)) {
      const fullPath = path.join(workflowDir, entry);
      if (fs.statSync(fullPath).isFile() && /\.(ya?ml)$/i.test(entry)) {
        files.push(fullPath);
      }
    }
  }
  const gitlab = path.join(rootDir, '.gitlab-ci.yml');
  if (fs.existsSync(gitlab)) {
    files.push(gitlab);
  }
  return files;
}

export function extractZipEntries(buffer: Uint8Array): Record<string, string> {
  const data = Buffer.from(buffer);
  const entries: Record<string, string> = {};
  const eocdOffset = findEndOfCentralDirectory(data);
  if (eocdOffset < 0) {
    return entries;
  }

  const totalEntries = data.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = data.readUInt32LE(eocdOffset + 16);
  let offset = centralDirectoryOffset;

  for (let index = 0; index < totalEntries; index += 1) {
    if (data.readUInt32LE(offset) !== 0x02014b50) {
      break;
    }

    const compressionMethod = data.readUInt16LE(offset + 10);
    const compressedSize = data.readUInt32LE(offset + 20);
    const fileNameLength = data.readUInt16LE(offset + 28);
    const extraLength = data.readUInt16LE(offset + 30);
    const commentLength = data.readUInt16LE(offset + 32);
    const localHeaderOffset = data.readUInt32LE(offset + 42);
    const fileName = data.subarray(offset + 46, offset + 46 + fileNameLength).toString('utf8');

    const localFileNameLength = data.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = data.readUInt16LE(localHeaderOffset + 28);
    const payloadStart = localHeaderOffset + 30 + localFileNameLength + localExtraLength;
    const payloadEnd = payloadStart + compressedSize;
    const payload = data.subarray(payloadStart, payloadEnd);

    if (!fileName.endsWith('/')) {
      if (compressionMethod === 0) {
        entries[fileName] = payload.toString('utf8');
      } else if (compressionMethod === 8) {
        entries[fileName] = zlib.inflateRawSync(payload).toString('utf8');
      }
    }

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  return entries;
}

function findEndOfCentralDirectory(buffer: any): number {
  for (let offset = buffer.length - 22; offset >= 0; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      return offset;
    }
  }
  return -1;
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
```

## 16. src/integrations/sarif.ts
```ts
import * as fs from 'node:fs';

import { ScanIssue } from '../types';

export function buildSarif(issues: ScanIssue[]): Record<string, unknown> {
  const rules = Array.from(
    new Map(
      issues.map((issue) => [
        issue.code,
        {
          id: issue.code,
          name: issue.code,
          shortDescription: { text: issue.title },
          fullDescription: { text: issue.description },
          properties: { tags: [issue.category] },
          help: { text: issue.recommendation ?? issue.description },
        },
      ]),
    ).values(),
  );

  const results = issues.map((issue) => ({
    ruleId: issue.code,
    level: sarifLevel(issue.severity),
    message: {
      text: `${issue.title}: ${issue.description}`,
    },
    locations: issue.location
      ? [
          {
            physicalLocation: {
              artifactLocation: {
                uri: issue.location,
              },
            },
          },
        ]
      : undefined,
    properties: {
      category: issue.category,
      severity: issue.severity,
      packageName: issue.packageName,
      packageVersion: issue.packageVersion,
      score: issue.score,
      evidence: issue.evidence,
      recommendation: issue.recommendation,
    },
  }));

  return {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'GuardRail',
            informationUri: 'https://github.com/guardrail-security/guardrail',
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function writeSarif(filePath: string, issues: ScanIssue[]): void {
  fs.writeFileSync(filePath, `${JSON.stringify(buildSarif(issues), null, 2)}\n`);
}

function sarifLevel(severity: ScanIssue['severity']): 'note' | 'warning' | 'error' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}
```

## 17. src/integrations/slack.ts
```ts
import { MonitorAlert } from '../types';

export async function sendSlackAlert(webhookUrl: string, alert: MonitorAlert): Promise<void> {
  const payload = {
    text: `GuardRail alert: ${alert.packageName}@${alert.version}`,
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `GuardRail: ${alert.packageName}@${alert.version}`,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Previous:* ${alert.previousVersion ?? 'unknown'}` },
          { type: 'mrkdwn', text: `*Publish method:* ${alert.publishMethod}` },
          { type: 'mrkdwn', text: `*Publisher:* ${alert.publishedBy ?? 'unknown'}` },
          { type: 'mrkdwn', text: `*Risk score:* ${String(alert.scriptRiskScore)}` },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Reasons:* ${alert.reasons.join('; ') || 'no suspicious deltas detected'}`,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*New dependencies:* ${alert.newDependencies.join(', ') || 'none'}\n*Added lifecycle scripts:* ${alert.addedLifecycleScripts.join(', ') || 'none'}\n*Ghost dependencies:* ${alert.ghostDependencies.join(', ') || 'none'}`,
        },
      },
    ],
  };

  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Slack webhook returned HTTP ${response.status}`);
  }
}
```

## 18. src/utils/registry.ts
```ts
import { RegistryPackageVersionMetadata } from '../types';

const DEFAULT_REGISTRY_BASE_URL = 'https://registry.npmjs.org';

export interface FetchOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export function parsePackageSpec(spec: string): { name: string; version?: string } {
  const trimmed = spec.trim();
  if (trimmed.length === 0) {
    throw new Error('Package spec cannot be empty.');
  }

  if (trimmed.startsWith('@')) {
    const separatorIndex = trimmed.lastIndexOf('@');
    if (separatorIndex > 0) {
      return {
        name: trimmed.slice(0, separatorIndex),
        version: trimmed.slice(separatorIndex + 1) || undefined,
      };
    }
    return { name: trimmed };
  }

  const separatorIndex = trimmed.lastIndexOf('@');
  if (separatorIndex > 0) {
    return {
      name: trimmed.slice(0, separatorIndex),
      version: trimmed.slice(separatorIndex + 1) || undefined,
    };
  }

  return { name: trimmed };
}

export function encodePackageName(packageName: string): string {
  return packageName.startsWith('@') ? `@${encodeURIComponent(packageName.slice(1))}` : encodeURIComponent(packageName);
}

export async function fetchText(url: string, options: FetchOptions = {}): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15000);

  try {
    const response = await fetch(url, {
      headers: options.headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${url}`);
    }

    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchJson<T>(url: string, options: FetchOptions = {}): Promise<T> {
  const text = await fetchText(url, options);
  return JSON.parse(text) as T;
}

export async function downloadBuffer(url: string, options: FetchOptions = {}): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 20000);

  try {
    const response = await fetch(url, {
      headers: options.headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${url}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchPackument(
  packageName: string,
  registryBaseUrl = DEFAULT_REGISTRY_BASE_URL,
): Promise<Record<string, unknown>> {
  const url = `${registryBaseUrl.replace(/\/$/, '')}/${encodePackageName(packageName)}`;
  return fetchJson<Record<string, unknown>>(url);
}

export async function fetchPackageVersion(
  packageName: string,
  version?: string,
  registryBaseUrl = DEFAULT_REGISTRY_BASE_URL,
): Promise<RegistryPackageVersionMetadata> {
  const packument = await fetchPackument(packageName, registryBaseUrl);
  const versions = (packument.versions ?? {}) as Record<string, unknown>;
  const distTags = (packument['dist-tags'] ?? {}) as Record<string, unknown>;
  const resolvedVersion = version ?? String(distTags.latest ?? '');

  if (!resolvedVersion) {
    throw new Error(`Could not resolve a version for ${packageName}`);
  }

  const metadata = versions[resolvedVersion];
  if (!metadata || typeof metadata !== 'object') {
    throw new Error(`Version ${resolvedVersion} not found for ${packageName}`);
  }

  return metadata as RegistryPackageVersionMetadata;
}

export function toRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object') {
    return value as Record<string, unknown>;
  }
  return {};
}

export function recursiveFindKey(value: unknown, keyName: string): unknown {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  if (keyName in record) {
    return record[keyName];
  }

  for (const nested of Object.values(record)) {
    const result = recursiveFindKey(nested, keyName);
    if (typeof result !== 'undefined') {
      return result;
    }
  }

  return undefined;
}

export function safeObjectEntries(value: unknown): [string, unknown][] {
  if (!value || typeof value !== 'object') {
    return [];
  }
  return Object.entries(value as Record<string, unknown>);
}
```

## 19. src/utils/lockfile.ts
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

import { LockfileInfo, PackageNode } from '../types';
import { parseJsonc } from '../core/baseline';

export function parseLockfile(rootDir: string): LockfileInfo {
  const candidates = [
    { kind: 'package-lock', path: path.join(rootDir, 'package-lock.json') },
    { kind: 'pnpm-lock', path: path.join(rootDir, 'pnpm-lock.yaml') },
    { kind: 'yarn-lock', path: path.join(rootDir, 'yarn.lock') },
    { kind: 'bun-lock', path: path.join(rootDir, 'bun.lock') },
    { kind: 'bun-lockb', path: path.join(rootDir, 'bun.lockb') },
  ] as const;

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate.path)) {
      continue;
    }

    switch (candidate.kind) {
      case 'package-lock':
        return parsePackageLock(candidate.path);
      case 'pnpm-lock':
        return parsePnpmLock(candidate.path);
      case 'yarn-lock':
        return parseYarnLock(candidate.path);
      case 'bun-lock':
        return parseBunLock(candidate.path);
      case 'bun-lockb':
        return parseBinaryBunLock(rootDir, candidate.path);
      default:
        break;
    }
  }

  return {
    kind: 'none',
    packages: [],
    directDependencies: {},
    warnings: ['No supported lockfile found. Scan will fall back to installed packages only.'],
  };
}

function parsePackageLock(filePath: string): LockfileInfo {
  const data = parseJsonc<Record<string, unknown>>(fs.readFileSync(filePath, 'utf8'));
  const packages: PackageNode[] = [];
  const warnings: string[] = [];
  let directDependencies: Record<string, string> = {};

  const packageEntries = (data.packages ?? {}) as Record<string, unknown>;
  if (Object.keys(packageEntries).length > 0) {
    const rootPackage = packageEntries[''] as Record<string, unknown> | undefined;
    directDependencies = normalizeDependencyRecord(rootPackage?.dependencies);

    for (const [packagePath, rawMeta] of Object.entries(packageEntries)) {
      if (packagePath === '' || !rawMeta || typeof rawMeta !== 'object') {
        continue;
      }
      const metadata = rawMeta as Record<string, unknown>;
      const name = String(metadata.name ?? inferNameFromNodeModulesPath(packagePath) ?? '');
      const version = String(metadata.version ?? '');
      if (!name || !version) {
        continue;
      }
      packages.push({
        name,
        version,
        dependencies: normalizeDependencyRecord(metadata.dependencies),
        resolved: typeof metadata.resolved === 'string' ? metadata.resolved : undefined,
        integrity: typeof metadata.integrity === 'string' ? metadata.integrity : undefined,
        path: packagePath,
        dev: Boolean(metadata.dev),
        optional: Boolean(metadata.optional),
      });
    }
  } else if (data.dependencies && typeof data.dependencies === 'object') {
    directDependencies = extractLegacyRootDependencies(data.dependencies as Record<string, unknown>);
    walkLegacyPackageLock('', data.dependencies as Record<string, unknown>, packages);
  } else {
    warnings.push('package-lock.json was present but no package entries were readable.');
  }

  return {
    kind: 'package-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function walkLegacyPackageLock(
  prefix: string,
  dependencies: Record<string, unknown>,
  packages: PackageNode[],
): void {
  for (const [name, rawMeta] of Object.entries(dependencies)) {
    if (!rawMeta || typeof rawMeta !== 'object') {
      continue;
    }
    const metadata = rawMeta as Record<string, unknown>;
    const version = String(metadata.version ?? '');
    if (!version) {
      continue;
    }
    packages.push({
      name,
      version,
      dependencies: normalizeDependencyRecord(metadata.requires),
      resolved: typeof metadata.resolved === 'string' ? metadata.resolved : undefined,
      integrity: typeof metadata.integrity === 'string' ? metadata.integrity : undefined,
      path: prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`,
      dev: Boolean(metadata.dev),
      optional: Boolean(metadata.optional),
    });

    const nested = metadata.dependencies;
    if (nested && typeof nested === 'object') {
      walkLegacyPackageLock(prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`, nested as Record<string, unknown>, packages);
    }
  }
}

function extractLegacyRootDependencies(dependencies: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, rawMeta] of Object.entries(dependencies)) {
    if (!rawMeta || typeof rawMeta !== 'object') {
      continue;
    }
    const version = (rawMeta as Record<string, unknown>).version;
    if (typeof version === 'string') {
      result[name] = version;
    }
  }
  return result;
}

function inferNameFromNodeModulesPath(packagePath: string): string | undefined {
  const normalized = packagePath.replace(/\\/g, '/');
  const marker = 'node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index === -1) {
    return undefined;
  }
  const tail = normalized.slice(index + marker.length);
  const parts = tail.split('/').filter(Boolean);
  const first = parts[0];
  const second = parts[1];
  if (first?.startsWith('@') && second) {
    return `${first}/${second}`;
  }
  return first;
}

function parsePnpmLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};
  const warnings: string[] = [];

  let section: 'none' | 'importers' | 'packages' = 'none';
  let importerSubsection = '';
  let currentDependencyName = '';
  let currentPackage: PackageNode | null = null;
  let packageSubsection = '';

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, '    ');
    const trimmed = line.trim();
    const indent = line.search(/\S|$/);

    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }

    if (trimmed === 'importers:') {
      section = 'importers';
      importerSubsection = '';
      currentDependencyName = '';
      currentPackage = null;
      continue;
    }

    if (trimmed === 'packages:') {
      section = 'packages';
      importerSubsection = '';
      currentDependencyName = '';
      currentPackage = null;
      continue;
    }

    if (section === 'importers') {
      if (indent === 2 && trimmed.endsWith(':')) {
        importerSubsection = '';
        currentDependencyName = '';
        continue;
      }

      if (indent === 4 && trimmed.endsWith(':')) {
        importerSubsection = trimmed.slice(0, -1);
        currentDependencyName = '';
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 6 && trimmed.endsWith(':')) {
        currentDependencyName = unquoteYaml(trimmed.slice(0, -1));
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 8 && trimmed.startsWith('version:')) {
        if (currentDependencyName) {
          directDependencies[currentDependencyName] = normalizePnpmVersionValue(trimmed.slice('version:'.length).trim());
        }
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 6 && trimmed.includes(':') && !trimmed.endsWith(':')) {
        const separator = trimmed.indexOf(':');
        const name = unquoteYaml(trimmed.slice(0, separator));
        const version = normalizePnpmVersionValue(trimmed.slice(separator + 1).trim());
        if (name && version) {
          directDependencies[name] = version;
        }
      }

      continue;
    }

    if (section === 'packages') {
      if (indent === 2 && trimmed.endsWith(':')) {
        const key = unquoteYaml(trimmed.slice(0, -1));
        const parsed = parsePnpmPackageKey(key);
        if (!parsed) {
          currentPackage = null;
          continue;
        }
        currentPackage = {
          name: parsed.name,
          version: parsed.version,
          dependencies: {},
          path: `pnpm:${key}`,
        };
        packages.push(currentPackage);
        packageSubsection = '';
        continue;
      }

      if (!currentPackage) {
        continue;
      }

      if (indent === 4 && trimmed.endsWith(':')) {
        packageSubsection = trimmed.slice(0, -1);
        continue;
      }

      if (indent === 4 && trimmed.startsWith('resolution:')) {
        const integrityMatch = trimmed.match(/integrity:\s*([^,}]+)/i);
        if (integrityMatch?.[1]) {
          currentPackage.integrity = normalizePnpmVersionValue(integrityMatch[1]);
        }
        continue;
      }

      if (packageSubsection === 'dependencies' && indent === 6 && trimmed.includes(':')) {
        const separator = trimmed.indexOf(':');
        const name = unquoteYaml(trimmed.slice(0, separator));
        const version = normalizePnpmVersionValue(trimmed.slice(separator + 1).trim());
        if (name && version) {
          currentPackage.dependencies[name] = version;
        }
      }
    }
  }

  if (packages.length === 0) {
    warnings.push('pnpm-lock.yaml could not be fully parsed. Falling back to installed packages is recommended.');
  }

  return {
    kind: 'pnpm-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function normalizePnpmVersionValue(input: string): string {
  const cleaned = unquoteYaml(input).replace(/^link:/, '').replace(/^workspace:/, '').trim();
  const separator = cleaned.indexOf('(');
  return separator >= 0 ? cleaned.slice(0, separator).trim() : cleaned;
}

function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
  const normalized = key.startsWith('/') ? key.slice(1) : key;
  const separator = normalized.lastIndexOf('@');
  if (separator <= 0) {
    return null;
  }
  const name = normalized.slice(0, separator);
  const version = normalizePnpmVersionValue(normalized.slice(separator + 1));
  if (!name || !version) {
    return null;
  }
  return { name, version };
}

function parseYarnLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const blocks = text.split(/\n{2,}/);
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};

  for (const block of blocks) {
    const lines = block
      .split(/\r?\n/)
      .map((line: string) => line.replace(/\r/g, ''))
      .filter((line: string) => line.trim().length > 0);

    if (lines.length === 0 || lines[0].startsWith('#')) {
      continue;
    }

    const keyLine = lines[0];
    const firstSpecifier = keyLine.split(',')[0]?.replace(/:$/, '').trim().replace(/^"|"$/g, '');
    if (!firstSpecifier) {
      continue;
    }

    const packageName = inferNameFromSpecifier(firstSpecifier);
    if (!packageName) {
      continue;
    }

    const node: PackageNode = {
      name: packageName,
      version: '',
      dependencies: {},
      path: `yarn:${packageName}`,
    };

    let subsection = '';
    for (const line of lines.slice(1)) {
      const trimmed = line.trim();
      if (trimmed.startsWith('version ')) {
        node.version = trimmed.replace(/^version\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed.startsWith('resolved ')) {
        node.resolved = trimmed.replace(/^resolved\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed.startsWith('integrity ')) {
        node.integrity = trimmed.replace(/^integrity\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed === 'dependencies:' || trimmed === 'optionalDependencies:') {
        subsection = trimmed.replace(/:$/, '');
        continue;
      }
      if ((subsection === 'dependencies' || subsection === 'optionalDependencies') && line.startsWith('    ')) {
        const match = trimmed.match(/^([^\s]+)\s+(.+)$/);
        if (match?.[1] && match[2]) {
          node.dependencies[match[1].replace(/^"|"$/g, '')] = match[2].replace(/^"|"$/g, '');
        }
      }
    }

    if (node.version) {
      packages.push(node);
      if (!(node.name in directDependencies)) {
        directDependencies[node.name] = node.version;
      }
    }
  }

  return {
    kind: 'yarn-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings: packages.length === 0 ? ['yarn.lock could not be parsed cleanly.'] : [],
  };
}

function parseBunLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const warnings: string[] = [];
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};

  if (/^\s*"[^"]+":\s*\[/m.test(text)) {
    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      const match = trimmed.match(/^"([^"]+)":\s*\[\s*"([^"]+)@([^"]+)"/);
      if (!match?.[1] || !match[2] || !match[3]) {
        continue;
      }
      const name = match[2];
      const version = match[3];
      packages.push({
        name,
        version,
        dependencies: {},
        path: `bun:${match[1]}`,
      });
      if (!(name in directDependencies)) {
        directDependencies[name] = version;
      }
    }
  } else {
    warnings.push('bun.lock format was not recognized. Falling back to installed packages is recommended.');
  }

  return {
    kind: 'bun-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function parseBinaryBunLock(rootDir: string, filePath: string): LockfileInfo {
  const warnings: string[] = [];
  try {
    const result = childProcess.spawnSync('bun', ['pm', 'ls', '--all', '--json'], {
      cwd: rootDir,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024,
    });

    if (result.status !== 0 || !result.stdout) {
      warnings.push(result.stderr?.trim() || 'bun pm ls --all --json failed');
      return {
        kind: 'bun-lockb',
        path: filePath,
        packages: [],
        directDependencies: {},
        warnings,
      };
    }

    const parsed = JSON.parse(result.stdout) as Array<Record<string, unknown>>;
    const packages: PackageNode[] = [];
    for (const entry of parsed) {
      const name = typeof entry.name === 'string' ? entry.name : '';
      const version = typeof entry.version === 'string' ? entry.version : '';
      if (!name || !version) {
        continue;
      }
      packages.push({
        name,
        version,
        dependencies: {},
        path: `bun:${name}`,
      });
    }

    return {
      kind: 'bun-lockb',
      path: filePath,
      packages: dedupePackages(packages),
      directDependencies: Object.fromEntries(packages.map((pkg) => [pkg.name, pkg.version])),
      warnings,
    };
  } catch (error) {
    return {
      kind: 'bun-lockb',
      path: filePath,
      packages: [],
      directDependencies: {},
      warnings: [`bun.lockb found but Bun was unavailable: ${formatError(error)}`],
    };
  }
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function inferNameFromSpecifier(specifier: string): string {
  const cleaned = specifier.replace(/^npm:/, '');
  if (cleaned.startsWith('@')) {
    const segments = cleaned.split('@');
    return segments.length >= 3 ? `@${segments[1]}` : cleaned;
  }
  return cleaned.split('@')[0] ?? cleaned;
}

function normalizeDependencyRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawVersion] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawVersion === 'string') {
      result[name] = rawVersion;
    }
  }
  return result;
}

function dedupePackages(packages: PackageNode[]): PackageNode[] {
  const seen = new Map<string, PackageNode>();
  for (const pkg of packages) {
    const key = `${pkg.path ?? pkg.name}:${pkg.name}@${pkg.version}`;
    if (!seen.has(key)) {
      seen.set(key, pkg);
    }
  }
  return Array.from(seen.values());
}

function unquoteYaml(input: string): string {
  return input.trim().replace(/^['"]|['"]$/g, '');
}
```

## 20. src/types/index.ts
```ts
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type PublishMethod = 'trusted-publishing' | 'manual-or-token' | 'unknown';

export type IntegrityStatus = 'verified' | 'mismatch' | 'partial' | 'not-checked';

export type SigstoreStatus = 'verified' | 'present-unverified' | 'not-found' | 'unknown';

export type TokenSourceType = 'env' | 'npmrc' | 'workflow' | 'npm-cli';

export type TokenKind = 'traditional-static' | 'granular-access-token' | 'session-token' | 'unknown';

export interface BaseCommandOptions {
  rootDir: string;
  configPath?: string;
  output?: string;
  json?: boolean;
  quiet?: boolean;
}

export interface ScanCommandOptions extends BaseCommandOptions {
  threshold?: number;
  failFast?: boolean;
  updateBaseline?: boolean;
  generateWorkflow?: boolean;
  installPreCommit?: boolean;
  sarif?: string;
}

export interface MonitorCommandOptions extends BaseCommandOptions {
  intervalMs?: number;
  slackWebhook?: string;
  webhook?: string;
  once?: boolean;
}

export interface AuditTokensCommandOptions extends BaseCommandOptions {
  revokeStale?: boolean;
  staleAfterDays?: number;
}

export interface VerifyCommandOptions extends BaseCommandOptions {
  packageSpec: string;
  failFast?: boolean;
}

export interface IncidentCommandOptions extends BaseCommandOptions {
  packageSpec: string;
  from: string;
  to: string;
  githubOwner?: string;
  githubRepo?: string;
  githubToken?: string;
}

export interface EmailConfig {
  host: string;
  port: number;
  secure?: boolean;
  username?: string;
  password?: string;
  from: string;
  to: string[];
}

export interface GitHubIntegrationConfig {
  owner?: string;
  repo?: string;
  token?: string;
  tokenEnvVar?: string;
}

export interface NotificationConfig {
  slackWebhook?: string;
  webhook?: string;
  email?: EmailConfig;
}

export interface ScanPolicyConfig {
  riskThreshold?: number;
  failOnSeverity?: Severity;
  ignoreDirs?: string[];
  trustedPackages?: string[];
  maxScriptFileBytes?: number;
}

export interface BaselineConfig {
  directory?: string;
  path?: string;
  privateKeyPath?: string;
  publicKeyPath?: string;
}

export interface TokenPolicyConfig {
  staleAfterDays?: number;
  mixedModeAllowed?: boolean;
}

export interface GuardrailConfig {
  baseline?: BaselineConfig;
  scan?: ScanPolicyConfig;
  notifications?: NotificationConfig;
  github?: GitHubIntegrationConfig;
  tokenPolicy?: TokenPolicyConfig;
  monitor?: {
    packages?: string[];
    pollIntervalMs?: number;
    slackWebhook?: string;
    webhook?: string;
    email?: EmailConfig;
  };
  __comment?: string;
  [key: string]: unknown;
}

export interface RegistryDistInfo {
  tarball?: string;
  integrity?: string;
  shasum?: string;
  signatures?: unknown;
  [key: string]: unknown;
}

export interface RegistryPackageVersionMetadata {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  dist?: RegistryDistInfo;
  repository?: string | { type?: string; url?: string };
  gitHead?: string;
  time?: string;
  _npmUser?: {
    name?: string;
    email?: string;
  };
  trustedPublisher?: unknown;
  [key: string]: unknown;
}

export interface PackageNode {
  name: string;
  version: string;
  dependencies: Record<string, string>;
  resolved?: string;
  integrity?: string;
  path?: string;
  dev?: boolean;
  optional?: boolean;
}

export interface LockfileInfo {
  kind: 'package-lock' | 'pnpm-lock' | 'yarn-lock' | 'bun-lock' | 'bun-lockb' | 'none';
  path?: string;
  packages: PackageNode[];
  directDependencies: Record<string, string>;
  warnings: string[];
}

export interface ScriptFinding {
  packageName: string;
  packageVersion: string;
  scriptName: string;
  command: string;
  score: number;
  severity: Severity;
  reasons: string[];
  evidence: string[];
}

export interface PackageSnapshot {
  name: string;
  version: string;
  packagePath?: string;
  declaredDependencies: string[];
  optionalDependencies: string[];
  peerDependencies: string[];
  importedDependencies: string[];
  unusedDeclaredDependencies: string[];
  lifecycleScripts: Record<string, string>;
  lifecycleScriptHashes: Record<string, string>;
  scriptFindings: ScriptFinding[];
  highestScriptRisk: number;
  sourceFileCount: number;
  manifestHash: string;
  sourceHash: string;
  packageHash: string;
  registry?: Pick<RegistryPackageVersionMetadata, 'gitHead' | 'repository' | '_npmUser' | 'trustedPublisher'>;
}

export interface BaselineSnapshot {
  generatedAt: string;
  rootManifestHash: string;
  lockfileHash?: string;
  packageManager?: LockfileInfo['kind'];
  packages: Record<string, PackageSnapshot>;
}

export interface BaselineFile {
  formatVersion: number;
  createdAt: string;
  updatedAt: string;
  publicKeyPem: string;
  signatureAlgorithm: 'ed25519';
  snapshot: BaselineSnapshot;
  signature: string;
}

export interface ScanIssue {
  id: string;
  code: string;
  category:
    | 'mutation'
    | 'ghost-dependency'
    | 'lifecycle-script'
    | 'token-exposure'
    | 'provenance'
    | 'integrity'
    | 'incident'
    | 'configuration';
  severity: Severity;
  title: string;
  description: string;
  packageName?: string;
  packageVersion?: string;
  dependencyName?: string;
  location?: string;
  score?: number;
  evidence?: string[];
  recommendation?: string;
  raw?: unknown;
}

export interface ScanExecutionResult {
  rootDir: string;
  generatedAt: string;
  baselinePath: string;
  baselineVerified: boolean;
  baselineCreated: boolean;
  lockfile: LockfileInfo;
  packagesScanned: number;
  lifecycleScriptsDiscovered: number;
  issues: ScanIssue[];
  packages: Record<string, PackageSnapshot>;
}

export interface FeedChange {
  sequence: number;
  packageName: string;
  deleted?: boolean;
  doc?: Record<string, unknown>;
}

export interface MonitorAlert {
  occurredAt: string;
  packageName: string;
  previousVersion?: string;
  version: string;
  publishedBy?: string;
  publisherEmail?: string;
  publishMethod: PublishMethod;
  hasTrustedPublisher: boolean;
  hasProvenance: boolean;
  newDependencies: string[];
  removedDependencies: string[];
  addedLifecycleScripts: string[];
  changedLifecycleScripts: string[];
  ghostDependencies: string[];
  scriptRiskScore: number;
  scriptFindings: ScriptFinding[];
  suspicious: boolean;
  reasons: string[];
}

export interface TokenDiscovery {
  sourceType: TokenSourceType;
  sourcePath?: string;
  envVar?: string;
  registry?: string;
  tokenPreview: string;
  tokenKind: TokenKind;
  canPublish?: boolean;
  bypass2FA?: boolean;
  createdAt?: string;
  lastUsedAt?: string;
  expiresAt?: string;
  id?: string;
  note?: string;
}

export interface TokenAuditResult {
  rootDir: string;
  oidcTrustedPublishingDetected: boolean;
  selfHostedRunnerDetected: boolean;
  staticPublishTokensFound: boolean;
  mixedModeRisk: boolean;
  findings: TokenDiscovery[];
  issues: ScanIssue[];
  suggestedRevocations: string[];
}

export interface IntegrityDiff {
  onlyInPackage: string[];
  modifiedInPackage: string[];
  overlapCount: number;
  matchRatio: number;
}

export interface VerificationResult {
  packageName: string;
  version: string;
  publishMethod: PublishMethod;
  publishedBy?: string;
  publisherEmail?: string;
  hasTrustedPublisher: boolean;
  hasProvenance: boolean;
  hasRegistrySignatures: boolean;
  slsaBuildLevel: 'unknown' | '1' | '2' | '3';
  sigstoreStatus: SigstoreStatus;
  integrityStatus: IntegrityStatus;
  sourceComparison?: IntegrityDiff;
  inconsistentProvenanceSignal: boolean;
  notes: string[];
  issues: ScanIssue[];
  metadata: Record<string, unknown>;
}

export interface WorkflowRunCandidate {
  id: number;
  name: string;
  htmlUrl: string;
  status: string;
  conclusion?: string;
  createdAt: string;
  updatedAt: string;
  possibleMatch: boolean;
  matches: string[];
}

export interface IncidentReport {
  packageName: string;
  version?: string;
  from: string;
  to: string;
  summary: string[];
  checklist: string[];
  possibleLocalMatches: string[];
  workflowRuns: WorkflowRunCandidate[];
  secretsAtRisk: string[];
  rotationCommands: Record<string, string[]>;
  issues: ScanIssue[];
}

export interface RemotePackageAnalysis {
  metadata: RegistryPackageVersionMetadata;
  snapshot: PackageSnapshot;
  tarballSha256: string;
  files: Record<string, Uint8Array>;
}
```

## 21. guardrail.config.json
```jsonc
{
  // Where GuardRail stores its signed dependency baseline and local signing keys.
  "baseline": {
    "directory": ".guardrail",
    "path": ".guardrail/baseline.json",
    "privateKeyPath": ".guardrail/baseline-private.pem",
    "publicKeyPath": ".guardrail/baseline-public.pem"
  },

  // Core scan policy.
  "scan": {
    "riskThreshold": 70,
    "failOnSeverity": "high",
    "trustedPackages": [
      "axios",
      "react",
      "next"
    ],
    "ignoreDirs": [
      "fixtures",
      "vendor"
    ],
    "maxScriptFileBytes": 256000
  },

  // Token hygiene policy.
  "tokenPolicy": {
    "staleAfterDays": 30,
    "mixedModeAllowed": false
  },

  // Optional GitHub integration for incident log scanning.
  "github": {
    "owner": "your-org",
    "repo": "your-repo",
    "tokenEnvVar": "GITHUB_TOKEN"
  },

  // Optional defaults for the live npm monitor.
  "monitor": {
    "packages": [
      "axios"
    ],
    "pollIntervalMs": 25000,
    "slackWebhook": "",
    "webhook": "",
    "email": {
      "host": "smtp.example.com",
      "port": 587,
      "secure": false,
      "username": "smtp-user",
      "password": "smtp-password",
      "from": "guardrail@example.com",
      "to": [
        "secops@example.com"
      ]
    }
  },

  // Optional shared notification defaults used by monitor alerts.
  "notifications": {
    "slackWebhook": "",
    "webhook": "",
    "email": {
      "host": "smtp.example.com",
      "port": 587,
      "secure": false,
      "username": "smtp-user",
      "password": "smtp-password",
      "from": "guardrail@example.com",
      "to": [
        "secops@example.com"
      ]
    }
  }
}
```

## 22. .github/workflows/guardrail.yml
```yaml
name: guardrail
on:
  push:
    branches:
      - main
      - master
  pull_request:

jobs:
  guardrail:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
      id-token: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: npm

      - name: Install GuardRail
        run: npm install -g guardrail-security

      - name: Run GuardRail scan before dependency install
        run: guardrail scan --fail-fast --sarif guardrail.sarif

      - name: Install dependencies without lifecycle scripts
        run: npm ci --ignore-scripts

      - name: Upload GuardRail SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardrail.sarif
```

## 23. README.md
```md
# GuardRail

GuardRail is an npm supply chain security guardian for the failure mode the axios compromise exposed: a trusted package suddenly adds a hidden dependency, that dependency runs a malicious postinstall hook, the release bypasses normal CI/CD provenance, and the package ecosystem treats it like a normal install.

GuardRail is CLI-first. It runs anywhere Node runs. It has no mandatory external service dependency for the core scan path.

## What GuardRail prevents

GuardRail is built to catch these classes of failure before they turn into silent code execution:

- sudden dependency mutation in a package you already trust
- ghost dependency injection, where a dependency is declared in `package.json` but never imported by source code
- risky `preinstall`, `install`, `postinstall`, `prepare`, and `prepublish` scripts across the full dependency tree
- mixed-mode publishing setups where OIDC trusted publishing exists but traditional npm publish credentials still exist locally or in CI
- releases that look like direct manual or token-based publishes instead of trusted-publisher releases
- provenance regressions, where one release is attested and the next is not
- rapid npm release events on packages you care about, with immediate diffing of dependency changes and install-time script changes

## Core capabilities

### 1. Dependency mutation detector

GuardRail keeps a signed baseline of package manifests and dependency sets. On each scan it compares the current dependency tree against that baseline and flags:

- new dependencies on packages that were already known
- same-version content drift
- lifecycle script additions or changes
- suspicious dependency expansion on mature packages

### 2. Ghost dependency detection

GuardRail scans package source files and builds an import graph. If a package adds a new dependency but never imports it, GuardRail marks it as a ghost dependency candidate.

That matters because postinstall droppers usually do not need to be imported by the parent package at all. They only need to be installed.

### 3. Postinstall script auditing

GuardRail enumerates lifecycle scripts across the dependency tree and risk-scores them for:

- network calls
- process spawning
- file writes and self-delete behavior
- base64 or hex payloads
- eval and dynamic code execution
- persistence paths and shell launchers

It blocks in fail-fast mode when a script exceeds the configured threshold.

### 4. Token exposure scanning

GuardRail searches:

- project `.npmrc`
- user `.npmrc`
- npm config paths
- environment variables
- CI workflow files
- `npm token list --json` output when available

It warns when a project appears to use OIDC trusted publishing but still has static publish tokens around.

### 5. Package integrity verification

For a package version, GuardRail can:

- fetch registry metadata
- infer whether the release looks trusted-published or manually published
- look for provenance and signature signals
- compare npm tarball contents with the GitHub source archive at `gitHead`
- flag missing provenance where peer packages in the same project do have it

### 6. Real-time npm monitoring

GuardRail can watch the npm change feed and alert when watched packages publish new versions. Each alert includes:

- previous version
- publish method
- publisher identity if available
- new dependencies
- added or changed lifecycle scripts
- ghost dependency candidates
- lifecycle script risk score

### 7. CI/CD integration and incident response

GuardRail ships with:

- a GitHub Actions workflow generator
- a pre-commit hook installer through `guardrail scan --install-pre-commit`
- SARIF output for GitHub code scanning
- an incident command that searches local project state, workflow secrets, and GitHub Actions logs in a chosen window

## Installation

### Run without installing globally

```bash
npx guardrail-security scan
```

### Global install

```bash
npm install -g guardrail-security
guardrail scan
```

### Local project install

```bash
npm install --save-dev guardrail-security
npx guardrail-security scan
```

## Commands

### `guardrail scan`

Scans the current project, loads or creates a signed baseline, inventories lifecycle scripts, and emits findings.

```bash
guardrail scan
```

Useful flags:

```bash
guardrail scan --fail-fast
guardrail scan --threshold 60
guardrail scan --sarif guardrail.sarif
guardrail scan --update-baseline
guardrail scan --generate-workflow
guardrail scan --install-pre-commit
guardrail scan --output guardrail-scan.json --json
```

### `guardrail monitor`

Watches the npm public change feed for packages in your dependency set or packages declared in `monitor.packages`.

```bash
guardrail monitor
guardrail monitor --interval-ms 10000
guardrail monitor --slack-webhook https://hooks.slack.com/services/...
guardrail monitor --webhook https://your-webhook.example/guardrail
```

### `guardrail audit-tokens`

Finds static publish tokens and mixed-mode publish risk.

```bash
guardrail audit-tokens
guardrail audit-tokens --revoke-stale --stale-after-days 30
```

### `guardrail verify`

Verifies a package version against registry metadata, provenance signals, and source contents.

```bash
guardrail verify axios@1.14.0
guardrail verify left-pad@1.3.0 --output verify.json --json
```

### `guardrail incident`

Builds an incident checklist, searches local manifests and lockfiles, and optionally scans GitHub Actions logs.

```bash
guardrail incident axios@1.14.1 --from 2026-03-31T00:00:00Z --to 2026-03-31T04:00:00Z
guardrail incident axios@1.14.1 --from 2026-03-31T00:00:00Z --to 2026-03-31T04:00:00Z \
  --github-owner your-org --github-repo your-repo --github-token "$GITHUB_TOKEN"
```

## Configuration

GuardRail reads `guardrail.config.json` from the project root. The file supports JSON-with-comments because GuardRail strips `//` and `/* ... */` comments before parsing.

Example:

```jsonc
{
  "scan": {
    "riskThreshold": 70,
    "failOnSeverity": "high",
    "trustedPackages": ["axios"]
  },
  "tokenPolicy": {
    "staleAfterDays": 30,
    "mixedModeAllowed": false
  },
  "github": {
    "owner": "your-org",
    "repo": "your-repo",
    "tokenEnvVar": "GITHUB_TOKEN"
  }
}
```

### Config reference

- `baseline.directory`: where GuardRail stores baseline data and signing keys
- `baseline.path`: signed baseline file path
- `baseline.privateKeyPath`: private signing key path
- `baseline.publicKeyPath`: public verification key path
- `scan.riskThreshold`: block threshold for lifecycle script score
- `scan.failOnSeverity`: minimum severity that fails CI in `--fail-fast` mode
- `scan.trustedPackages`: packages whose dependency mutation should be treated as especially sensitive
- `scan.ignoreDirs`: extra source-tree directories to skip while building import graphs
- `scan.maxScriptFileBytes`: max referenced script file size GuardRail will read while scoring
- `tokenPolicy.staleAfterDays`: revocation suggestion horizon
- `tokenPolicy.mixedModeAllowed`: set to `true` only if you knowingly accept OIDC plus token publishing
- `monitor.packages`: explicit package watch list for daemon mode
- `monitor.pollIntervalMs`: npm change-feed long-poll timeout
- `monitor.slackWebhook`: default Slack webhook
- `monitor.webhook`: generic JSON webhook
- `monitor.email`: SMTP settings for email alerts
- `notifications.*`: shared notification defaults for commands that send alerts
- `github.owner` / `github.repo` / `github.tokenEnvVar`: defaults for incident log scanning

## How to respond to an alert

### Dependency mutation or ghost dependency

1. stop installs that resolve the flagged release
2. pin to the last known-good version
3. inspect the package diff and tarball
4. run `guardrail verify <pkg>@<version>`
5. if installation happened already, treat the machine as potentially compromised

### Risky lifecycle script

1. re-run installs with `--ignore-scripts`
2. inspect the script body and referenced files
3. look for network fetches, shell launchers, encoded payloads, and self-delete logic
4. quarantine build agents or developer endpoints that already executed it

### Mixed-mode publishing risk

1. keep OIDC trusted publishing
2. switch package publishing access to “require two-factor authentication and disallow tokens”
3. revoke static write tokens
4. keep only short-lived read credentials where private installs still need them

## How the axios attack would have been caught

GuardRail would have tripped multiple independent controls:

1. **Dependency mutation detector**: `axios@1.14.1` and `axios@0.30.4` introduced a new dependency that prior baselines did not contain.
2. **Ghost dependency detector**: `plain-crypto-js` was not imported anywhere in the parent package source, so the new dependency would be flagged as ghost-like.
3. **Postinstall script auditor**: the added package contains a `postinstall` hook running `node setup.js`; GuardRail would score the script and referenced file for network fetches, process execution, file writes, obfuscation, and self-delete behavior.
4. **Token exposure scanner**: if the maintainer environment or CI still had static publish credentials alongside trusted publishing, GuardRail would call that out as a critical mixed-mode risk.
5. **Package integrity verifier**: the malicious release would be marked as a manual-or-token publish instead of a trusted-publisher release, and provenance absence would stand out.
6. **npm feed monitor**: teams watching `axios` would receive an alert as soon as the new release appeared, including the new dependency and lifecycle-script delta.

## Output formats

GuardRail supports:

- normal CLI output
- JSON output with `--json` and `--output`
- SARIF output with `guardrail scan --sarif guardrail.sarif`

## Operational notes

- `scan` works offline for core local analysis when `node_modules` or lockfiles are present.
- `verify` and `monitor` need network access to the npm registry and, for source comparison, to the source host.
- GitHub Actions log scanning requires a GitHub token.
- SMTP email alerts require reachable SMTP infrastructure.
- The source-vs-tarball compare is strongest on repositories that publish directly from repo root. Monorepos or packages with generated build artifacts may produce `partial` instead of `verified`.

## Development

Build:

```bash
npm run build
```

Run from source output after building:

```bash
node dist/src/index.js scan
```

## License

MIT
```

## 24. INSTALL.md
```md
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
```

## Quick Start

```bash
npm install
npm run build
cp guardrail.config.json /path/to/your-node-project/guardrail.config.json
cd /path/to/your-node-project
node /path/to/guardrail/dist/src/index.js scan --fail-fast --sarif guardrail.sarif
```
