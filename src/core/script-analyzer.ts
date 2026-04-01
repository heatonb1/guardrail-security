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
  {
    id: 'xor-cipher',
    weight: 22,
    reason: 'XOR cipher pattern (common in dropper payloads)',
    patterns: [
      /charCodeAt\s*\([^)]*\)\s*\^\s*/i,
      /\^\s*charCodeAt\s*\(/i,
      /\bxor\b.*\bkey\b/i,
      /\bkey\b.*\bxor\b/i,
    ],
  },
  {
    id: 'self-modify',
    weight: 20,
    reason: 'self-modifying or self-deleting install script',
    patterns: [
      /writeFileSync\s*\([^)]*package\.json/i,
      /writeFile\s*\([^)]*package\.json/i,
      /unlinkSync\s*\([^)]*__filename/i,
      /unlink\s*\([^)]*__filename/i,
      /rm\s+-[rf]+\s+.*\$\{?__dirname/i,
      /process\.mainModule/i,
    ],
  },
  {
    id: 'credential-access',
    weight: 22,
    reason: 'credential or secret access patterns',
    patterns: [
      /\.ssh\//i,
      /id_rsa/i,
      /authorized_keys/i,
      /\.aws\/credentials/i,
      /169\.254\.169\.254/,
      /AWS_SECRET_ACCESS_KEY/i,
      /AWS_ACCESS_KEY_ID/i,
      /AZURE_CLIENT_SECRET/i,
      /GOOGLE_APPLICATION_CREDENTIALS/i,
    ],
  },
  {
    id: 'exfiltration',
    weight: 24,
    reason: 'data exfiltration pattern',
    patterns: [
      /\.post\s*\([^)]*process\.env/i,
      /fetch\s*\([^)]*\{[^}]*method\s*:\s*['"]POST['"]/i,
      /XMLHttpRequest[^;]*\.send\s*\([^)]*env/i,
      /https?:\/\/[^\s]+.*process\.env/i,
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

function calculateCompoundBonus(matchedRuleIds: string[]): { bonus: number; reasons: string[] } {
  const ids = new Set(matchedRuleIds);
  let bonus = 0;
  const reasons: string[] = [];

  // XOR + base64/eval + network = axios RAT dropper signature
  if (ids.has('xor-cipher') && (ids.has('eval') || ids.has('obfuscation')) && ids.has('network')) {
    bonus += 25;
    reasons.push('compound: XOR + encoding + network (matches axios RAT dropper signature)');
  }

  // Obfuscation + network = concealed C2
  if (ids.has('obfuscation') && ids.has('network') && !reasons.some(r => r.includes('XOR'))) {
    bonus += 15;
    reasons.push('compound: obfuscation + network (concealed C2 communication)');
  }

  // Network + platform-specific paths = cross-platform dropper
  if (ids.has('network') && (ids.has('persistence') || ids.has('file-system'))) {
    bonus += 20;
    reasons.push('compound: network + filesystem/persistence (cross-platform dropper pattern)');
  }

  // Self-modify + network = anti-forensic payload delivery
  if (ids.has('self-modify') && ids.has('network')) {
    bonus += 30;
    reasons.push('compound: self-modification + network (anti-forensic payload delivery)');
  }

  // Credential access + network = credential theft
  if (ids.has('credential-access') && ids.has('network')) {
    bonus += 20;
    reasons.push('compound: credential access + network (credential exfiltration)');
  }

  return { bonus, reasons };
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
  const matchedRuleIds: string[] = [];

  for (const rule of RULES) {
    const matched = rule.patterns.some((pattern) => pattern.test(text));
    if (!matched) {
      continue;
    }
    score += rule.weight;
    reasons.push(rule.reason);
    evidence.push(rule.id);
    matchedRuleIds.push(rule.id);
  }

  const compoundResult = calculateCompoundBonus(matchedRuleIds);
  if (compoundResult.bonus > 0) {
    score += compoundResult.bonus;
    reasons.push(...compoundResult.reasons);
    evidence.push('compound-bonus');
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
