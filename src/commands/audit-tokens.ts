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
