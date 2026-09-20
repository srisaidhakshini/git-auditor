/**
 * scanner.ts — Secrets engine.
 *
 * Wraps `gitleaks detect` when available, with a built-in native Git secret scanner fallback.
 * Secret values are ALWAYS masked before leaving this module.
 */

import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCommand } from '../../utils/shell.js';
import { maskSecret } from '../../utils/mask.js';
import { logger } from '../../utils/logger.js';
import type {
  SecretFinding,
  SecretScanResult,
  ScanMode,
  SecretType,
  GitleaksRawFinding,
} from './types.js';

const GITLEAKS_INSTALL_HINT =
  'https://github.com/gitleaks/gitleaks#installing\n' +
  '  macOS:   brew install gitleaks\n' +
  '  Linux:   Download from https://github.com/gitleaks/gitleaks/releases\n' +
  '  Windows: winget install gitleaks or choco install gitleaks';

/**
 * Maps gitleaks rule IDs to our normalized SecretType enum.
 */
function classifyRuleId(ruleId: string): SecretType {
  const id = ruleId.toLowerCase();
  if (id.includes('aws') && id.includes('access')) return 'aws-access-key';
  if (id.includes('aws') && id.includes('secret')) return 'aws-secret-key';
  if (id.includes('github')) return 'github-token';
  if (id.includes('private-key') || id.includes('rsa')) return 'private-key';
  if (id.includes('jwt')) return 'jwt';
  if (id.includes('stripe')) return 'stripe-key';
  if (id.includes('sendgrid')) return 'sendgrid-key';
  if (id.includes('slack')) return 'slack-token';
  if (id.includes('twilio')) return 'twilio-key';
  if (id.includes('google')) return 'google-api-key';
  if (id.includes('generic') || id.includes('api-key') || id.includes('api_key'))
    return 'generic-api-key';
  return 'unknown';
}

/**
 * Parses raw gitleaks JSON output into typed, masked SecretFinding objects.
 */
function parseGitleaksOutput(raw: string, repoPath: string): SecretFinding[] {
  let items: GitleaksRawFinding[];
  try {
    items = JSON.parse(raw) as GitleaksRawFinding[];
  } catch {
    return [];
  }

  if (!Array.isArray(items)) return [];

  const seen = new Set<string>();
  const findings: SecretFinding[] = [];

  for (const item of items) {
    if (seen.has(item.Fingerprint)) continue;
    seen.add(item.Fingerprint);

    const maskedValue = maskSecret(item.Secret);
    const filePath = item.File.startsWith(repoPath)
      ? item.File.slice(repoPath.length).replace(/^[\\/]/, '')
      : item.File;

    findings.push({
      secretType: classifyRuleId(item.RuleID),
      maskedValue,
      ruleId: item.RuleID,
      filePath,
      commitSha: item.Commit || null,
      author: item.Author || null,
      commitDate: item.Date || null,
      lineNumber: item.StartLine ?? null,
      fingerprint: item.Fingerprint,
    });
  }

  return findings;
}

interface FallbackRule {
  id: string;
  type: SecretType;
  regex: RegExp;
}

const BUILTIN_RULES: FallbackRule[] = [
  {
    id: 'aws-access-key-id',
    type: 'aws-access-key',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
  },
  {
    id: 'aws-secret-access-key',
    type: 'aws-secret-key',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?/i,
  },
  {
    id: 'github-pat',
    type: 'github-token',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/,
  },
  {
    id: 'private-key',
    type: 'private-key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: 'stripe-api-key',
    type: 'stripe-key',
    regex: /(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,99}/,
  },
  {
    id: 'sendgrid-api-key',
    type: 'sendgrid-key',
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
  },
  {
    id: 'generic-env-secret',
    type: 'generic-api-key',
    regex: /(?:API_KEY|SECRET|PASSWORD|AUTH_TOKEN|DATABASE_URL|ACCESS_TOKEN)\s*=\s*["']?([^\s"']{8,})["']?/i,
  },
];

/**
 * Built-in native Git secret scanner fallback when gitleaks binary is not installed.
 */
async function runNativeFallbackScan(
  repoPath: string,
  mode: ScanMode,
): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];
  const seenFingerprints = new Set<string>();

  // 1. Scan git log history for committed diffs and secrets
  if (mode === 'full-history') {
    const gitLogRes = await runCommand(
      'git',
      ['log', '-p', '--all', '--format=COMMIT_META:%H|%an|%ad'],
      { cwd: repoPath },
    );

    if (gitLogRes.exitCode === 0 && gitLogRes.stdout) {
      const commitBlocks = gitLogRes.stdout.split('COMMIT_META:');
      for (const block of commitBlocks) {
        if (!block.trim()) continue;
        const lines = block.split('\n');
        const header = lines[0] || '';
        const [commitSha = '', author = '', commitDate = ''] = header.split('|');

        let currentFile = '';
        let lineNo = 0;

        for (const line of lines.slice(1)) {
          if (line.startsWith('diff --git')) {
            const match = line.match(/b\/(.*)$/);
            currentFile = match ? match[1]! : '';
            lineNo = 0;
            continue;
          }

          if (line.startsWith('+++') || line.startsWith('---')) continue;
          if (line.startsWith('+')) {
            lineNo++;
            const addedText = line.slice(1);

            // Special check: .env files committed to git
            const isEnvFile = /(^|[\\/])\.env(\.[a-zA-Z0-9_-]+)?$/i.test(currentFile);
            if (isEnvFile && !currentFile.endsWith('.example') && addedText.includes('=')) {
              const fingerprint = `${commitSha}:${currentFile}:${lineNo}`;
              if (!seenFingerprints.has(fingerprint)) {
                seenFingerprints.add(fingerprint);
                findings.push({
                  secretType: 'generic-api-key',
                  maskedValue: maskSecret(addedText.trim()),
                  ruleId: 'committed-env-file',
                  filePath: currentFile,
                  commitSha,
                  author,
                  commitDate,
                  lineNumber: lineNo,
                  fingerprint,
                });
              }
            }

            // Check against rules
            for (const rule of BUILTIN_RULES) {
              const m = addedText.match(rule.regex);
              if (m) {
                const secretVal = m[1] || m[0];
                const fingerprint = `${commitSha}:${currentFile}:${rule.id}:${lineNo}`;
                if (!seenFingerprints.has(fingerprint)) {
                  seenFingerprints.add(fingerprint);
                  findings.push({
                    secretType: rule.type,
                    maskedValue: maskSecret(secretVal),
                    ruleId: rule.id,
                    filePath: currentFile,
                    commitSha,
                    author,
                    commitDate,
                    lineNumber: lineNo,
                    fingerprint,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  // 2. Working tree file scanning
  function scanDirectory(dir: string) {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (entry === '.git' || entry === 'node_modules') continue;
      const fullPath = join(dir, entry);
      const relPath = fullPath.slice(repoPath.length).replace(/^[\\/]/, '');

      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        scanDirectory(fullPath);
      } else if (stat.isFile() && stat.size < 1024 * 1024) {
        // Check .env files
        const isEnvFile = /(^|[\\/])\.env(\.[a-zA-Z0-9_-]+)?$/i.test(entry);
        try {
          const content = readFileSync(fullPath, 'utf8');
          const lines = content.split('\n');

          if (isEnvFile && !entry.endsWith('.example')) {
            for (let i = 0; i < lines.length; i++) {
              const l = lines[i]?.trim();
              if (l && l.includes('=') && !l.startsWith('#')) {
                const fp = `wt:${relPath}:${i + 1}`;
                if (!seenFingerprints.has(fp)) {
                  seenFingerprints.add(fp);
                  findings.push({
                    secretType: 'generic-api-key',
                    maskedValue: maskSecret(l),
                    ruleId: 'committed-env-file',
                    filePath: relPath,
                    commitSha: null,
                    author: null,
                    commitDate: null,
                    lineNumber: i + 1,
                    fingerprint: fp,
                  });
                }
              }
            }
          }

          // Check rule patterns in file content
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i] || '';
            for (const rule of BUILTIN_RULES) {
              const m = line.match(rule.regex);
              if (m) {
                const secretVal = m[1] || m[0];
                const fp = `wt:${relPath}:${rule.id}:${i + 1}`;
                if (!seenFingerprints.has(fp)) {
                  seenFingerprints.add(fp);
                  findings.push({
                    secretType: rule.type,
                    maskedValue: maskSecret(secretVal),
                    ruleId: rule.id,
                    filePath: relPath,
                    commitSha: null,
                    author: null,
                    commitDate: null,
                    lineNumber: i + 1,
                    fingerprint: fp,
                  });
                }
              }
            }
          }
        } catch {
          // ignore unreadable files
        }
      }
    }
  }

  try {
    scanDirectory(repoPath);
  } catch {}

  return findings;
}

/**
 * Scans a local repo path for secrets using gitleaks or native fallback scanner.
 */
export async function scanSecrets(
  repoPath: string,
  repoFullName: string,
  mode: ScanMode = 'full-history',
  timeoutMs = 0,
): Promise<SecretScanResult> {
  const startMs = Date.now();

  if (!existsSync(repoPath)) {
    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings: [],
      durationMs: Date.now() - startMs,
      success: false,
      error: `Path does not exist: ${repoPath}`,
    };
  }

  // 1. Check if gitleaks is installed
  let hasGitleaks = false;
  try {
    hasGitleaks = (await runCommand('gitleaks', ['version'])).exitCode === 0;
  } catch {
    hasGitleaks = false;
  }

  if (!hasGitleaks) {
    logger.debug('gitleaks not found in PATH — running native fallback secret scanner.');
    const fallbackFindings = await runNativeFallbackScan(repoPath, mode);
    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings: fallbackFindings,
      durationMs: Date.now() - startMs,
      success: true,
    };
  }

  // 2. Run gitleaks
  const tmpDir = mkdtempSync(join(tmpdir(), 'repo-guardian-'));
  const reportFile = join(tmpDir, 'gitleaks-report.json');

  try {
    const args: string[] = [
      'detect',
      '--source', repoPath,
      '--report-format', 'json',
      '--report-path', reportFile,
      '--exit-code', '0',
      '--no-banner',
    ];

    if (mode === 'full-history') {
      args.push('--log-opts', '--all');
    } else {
      args.push('--no-git');
    }

    logger.info(`Running gitleaks (${mode}) on ${repoFullName}...`);

    const result = await runCommand('gitleaks', args, {
      cwd: repoPath,
      timeoutMs: timeoutMs > 0 ? timeoutMs : undefined,
    });

    if (result.exitCode === 124) {
      return {
        repoFullName,
        scannedPath: repoPath,
        mode,
        findings: [],
        durationMs: Date.now() - startMs,
        success: false,
        error: `Scan timed out after ${timeoutMs}ms`,
      };
    }

    let rawReport = '';
    if (existsSync(reportFile)) {
      rawReport = readFileSync(reportFile, 'utf8');
    }

    const findings = parseGitleaksOutput(rawReport, repoPath);

    // If gitleaks didn't catch specific .env files, supplement with native detector
    const nativeFindings = await runNativeFallbackScan(repoPath, mode);
    for (const nf of nativeFindings) {
      if (!findings.some((f) => f.filePath === nf.filePath && f.lineNumber === nf.lineNumber)) {
        findings.push(nf);
      }
    }

    const durationMs = Date.now() - startMs;
    logger.info(`Scan complete: ${findings.length} finding(s) in ${repoFullName} (${durationMs}ms)`);

    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings,
      durationMs,
      success: true,
    };
  } catch (err) {
    // Fallback on error
    const fallbackFindings = await runNativeFallbackScan(repoPath, mode);
    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings: fallbackFindings,
      durationMs: Date.now() - startMs,
      success: true,
    };
  } finally {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
}
