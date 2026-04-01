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
