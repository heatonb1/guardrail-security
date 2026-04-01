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
