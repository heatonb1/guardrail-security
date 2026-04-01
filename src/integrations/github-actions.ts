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
