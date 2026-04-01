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
