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
