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
