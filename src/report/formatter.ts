/**
 * formatter.ts — Terminal report renderer.
 *
 * Produces a human-readable, colour-coded summary of findings
 * grouped by: repo → engine → severity.
 *
 * SAFETY: Only masked values from SecretFinding.maskedValue are printed.
 */

import chalk, { type ChalkInstance } from 'chalk';
import type { ScanReport } from './types.js';
import type { SecretFinding } from '../engines/secrets/types.js';

// ─── Colour helpers ───────────────────────────────────────────────────────────

const c = {
  heading: chalk.bold.cyan,
  repo: chalk.bold.white,
  critical: chalk.bold.red,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.green,
  info: chalk.gray,
  dim: chalk.dim,
  success: chalk.bold.green,
  warn: chalk.bold.yellow,
  label: chalk.bold,
  value: chalk.white,
};

function severityColor(type: SecretFinding['secretType']): ChalkInstance {
  // Map secret types to rough severity colours
  const critical = ['aws-access-key', 'aws-secret-key', 'private-key', 'github-token'];
  const high = ['stripe-key', 'sendgrid-key', 'twilio-key', 'google-api-key'];
  if (critical.includes(type)) return c.critical;
  if (high.includes(type)) return c.high;
  return c.medium;
}

// ─── Rotation reminder (mandatory per PRD §5) ─────────────────────────────────

const ROTATION_REMINDER = chalk.bold.red(
  '\n⚠️  IMPORTANT: Cleaning history does NOT undo exposure.\n' +
    '   Any credential found in git history should be considered compromised.\n' +
    '   Rotate it at your provider console NOW, before anything else.\n',
);

// ─── Per-finding block ────────────────────────────────────────────────────────

function renderFinding(finding: SecretFinding, index: number): string {
  const color = severityColor(finding.secretType);
  const lines: string[] = [];

  lines.push(
    color(`  [${index + 1}] ${finding.secretType.toUpperCase()}`) +
      c.dim(` (rule: ${finding.ruleId})`),
  );
  lines.push(`      ${c.label('File:')}   ${c.value(finding.filePath)}`);

  if (finding.commitSha) {
    lines.push(`      ${c.label('Commit:')} ${c.value(finding.commitSha.slice(0, 12))}` +
      (finding.author ? c.dim(` by ${finding.author}`) : '') +
      (finding.commitDate ? c.dim(` on ${finding.commitDate.slice(0, 10)}`) : ''));
  }

  if (finding.lineNumber) {
    lines.push(`      ${c.label('Line:')}   ${c.value(String(finding.lineNumber))}`);
  }

  lines.push(`      ${c.label('Value:')}  ${c.warn(finding.maskedValue)}`);
  lines.push('');

  return lines.join('\n');
}

// ─── Per-repo block ───────────────────────────────────────────────────────────

function renderRepo(repoFullName: string, htmlUrl: string, findings: SecretFinding[]): string {
  const lines: string[] = [];

  const bar = '─'.repeat(60);
  lines.push(c.heading(`\n${bar}`));
  lines.push(c.repo(`  📦 ${repoFullName}`) + c.dim(`  ${htmlUrl}`));
  lines.push(c.heading(bar));

  if (findings.length === 0) {
    lines.push(c.success('  ✅ No secrets found\n'));
    return lines.join('\n');
  }

  lines.push(
    c.critical(`  🔴 ${findings.length} secret(s) found`) + c.dim(' — masked values shown below'),
  );
  lines.push('');

  for (let i = 0; i < findings.length; i++) {
    lines.push(renderFinding(findings[i]!, i));
  }

  return lines.join('\n');
}

// ─── Main render function ─────────────────────────────────────────────────────

/**
 * Renders a full scan report to a human-readable terminal string.
 * Safe to write directly to process.stdout.
 */
export function renderTerminalReport(report: ScanReport): string {
  const lines: string[] = [];

  lines.push(
    c.heading('\n╔══════════════════════════════════════════════════════════╗'),
  );
  lines.push(
    c.heading('║           REPO GUARDIAN — SECURITY SCAN REPORT           ║'),
  );
  lines.push(
    c.heading('╚══════════════════════════════════════════════════════════╝'),
  );
  lines.push(c.dim(`  Generated: ${report.generatedAt}`));
  lines.push(c.dim(`  Repos scanned: ${report.totalRepos}  |  Total findings: ${report.totalFindings}`));

  for (const repo of report.repos) {
    const findings = repo.secrets?.findings ?? [];
    lines.push(renderRepo(repo.repoFullName, repo.htmlUrl, findings));

    // Mandatory rotation reminder if secrets were found
    if (findings.length > 0) {
      lines.push(ROTATION_REMINDER);
    }
  }

  // Summary footer
  lines.push(c.heading('─'.repeat(62)));
  if (report.totalFindings === 0) {
    lines.push(c.success('  ✅ All repos clean — no secrets detected.\n'));
  } else {
    lines.push(
      c.critical(`  ⚠️  ${report.totalFindings} secret(s) detected across ${report.totalRepos} repo(s).`),
    );
    lines.push(
      c.warn('  Next step: run  repo-guardian clean <repo>  to strip from history.\n'),
    );
  }

  return lines.join('\n');
}

/**
 * Renders the report as compact, machine-readable JSON.
 * Secret values are masked in the underlying data — safe to pipe.
 */
export function renderJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
