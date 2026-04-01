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
