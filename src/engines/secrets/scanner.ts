/**
 * scanner.ts — Secrets engine.
 *
 * Wraps `gitleaks detect` to scan a local repo path for committed secrets.
 * Secret values are ALWAYS masked before leaving this module.
 */

import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCommand, assertBinaryExists } from '../../utils/shell.js';
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
 * Rule IDs that don't match fall back to 'unknown'.
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
 * The raw Secret field is consumed here and immediately masked — it must
 * not be forwarded anywhere else.
 */
function parseGitleaksOutput(raw: string, repoPath: string): SecretFinding[] {
  let items: GitleaksRawFinding[];
  try {
    items = JSON.parse(raw) as GitleaksRawFinding[];
  } catch {
    // gitleaks outputs an empty string or "[]" when no findings
    return [];
  }

  if (!Array.isArray(items)) return [];

  // Deduplicate by fingerprint
  const seen = new Set<string>();
  const findings: SecretFinding[] = [];

  for (const item of items) {
    if (seen.has(item.Fingerprint)) continue;
    seen.add(item.Fingerprint);

    // SAFETY: maskSecret() is called immediately on the raw secret value.
    // item.Secret must never be forwarded outside this loop.
    const maskedValue = maskSecret(item.Secret);

    // Make file path relative to repo root for cleaner output
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

/**
 * Scans a local repo path for secrets using gitleaks.
 *
 * @param repoPath - Absolute path to a local git repository.
 * @param repoFullName - The "owner/name" identifier for reporting.
 * @param mode - 'full-history' (default) or 'working-tree'.
 * @param timeoutMs - Optional scan timeout. 0 = no limit.
 */
export async function scanSecrets(
  repoPath: string,
  repoFullName: string,
  mode: ScanMode = 'full-history',
  timeoutMs = 0,
): Promise<SecretScanResult> {
  const startMs = Date.now();

  // 1. Ensure gitleaks is available
  try {
    await assertBinaryExists('gitleaks', GITLEAKS_INSTALL_HINT);
  } catch (err) {
    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings: [],
      durationMs: Date.now() - startMs,
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // 2. Validate the target path
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

  // 3. Create a temp file for gitleaks JSON report
  const tmpDir = mkdtempSync(join(tmpdir(), 'repo-guardian-'));
  const reportFile = join(tmpDir, 'gitleaks-report.json');

  try {
    // 4. Build gitleaks args
    const args: string[] = [
      'detect',
      '--source', repoPath,
      '--report-format', 'json',
      '--report-path', reportFile,
      '--exit-code', '0', // don't fail on findings — we parse the report ourselves
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

    // gitleaks exit code 1 means "findings found" when --exit-code isn't set
    // We used --exit-code 0 so non-zero here is a real error
    if (result.exitCode > 1) {
      logger.warn('gitleaks stderr:', { stderr: result.stderr.slice(0, 500) });
    }

    // 5. Read and parse the JSON report from disk (safer than parsing stdout)
    const { readFileSync } = await import('node:fs');
    let rawReport = '';
    if (existsSync(reportFile)) {
      rawReport = readFileSync(reportFile, 'utf8');
    }

    const findings = parseGitleaksOutput(rawReport, repoPath);
    const durationMs = Date.now() - startMs;

    logger.info(
      `Scan complete: ${findings.length} finding(s) in ${repoFullName} (${durationMs}ms)`,
    );

    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings,
      durationMs,
      success: true,
    };
  } catch (err) {
    return {
      repoFullName,
      scannedPath: repoPath,
      mode,
      findings: [],
      durationMs: Date.now() - startMs,
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    // Clean up temp dir
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}
