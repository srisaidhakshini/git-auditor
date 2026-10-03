/**
 * compact.ts — Short, readable terminal summary of a scan.
 *
 * Secrets are grouped (same file + rule + value = one entry, however many commits it
 * appears in) and dependency CVEs are summarised as "how to fix" actions instead of one
 * block per vulnerable package. The full list is available with `--details`.
 *
 * SAFETY: Only masked values are printed.
 */

import chalk from 'chalk';
import type { ScanReport, RepoReport, Severity } from './types.js';
import type { SecretFinding } from '../engines/secrets/types.js';
import type { DependencyFinding } from '../engines/deps/types.js';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const rank = (s: Severity): number => SEVERITIES.indexOf(s);

const sevColor = (s: Severity) =>
  s === 'critical' ? chalk.bold.red : s === 'high' ? chalk.red : s === 'medium' ? chalk.yellow : chalk.green;

const badge = (s: Severity): string => sevColor(s)(s.toUpperCase().padEnd(8));

const MAX_SECRET_GROUPS = 8;
const MAX_TOP_ISSUES = 5;
const MAX_FIX_GROUPS = 6;

// ─── Secrets ──────────────────────────────────────────────────────────────────

export interface SecretGroup {
  filePath: string;
  type: string;
  ruleId: string;
  maskedValue: string;
  occurrences: number;
  commitSha: string | null;
  author: string | null;
  commitDate: string | null;
  inCurrentFiles: boolean;
}

/** Collapses repeated findings (history + working tree, many commits) into one entry each. */
export function groupSecrets(findings: SecretFinding[]): SecretGroup[] {
  const groups = new Map<string, SecretGroup>();
  for (const f of findings) {
    const key = `${f.filePath}|${f.ruleId}|${f.maskedValue}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        filePath: f.filePath,
        type: f.secretType,
        ruleId: f.ruleId,
        maskedValue: f.maskedValue,
        occurrences: 0,
        commitSha: null,
        author: null,
        commitDate: null,
        inCurrentFiles: false,
      };
      groups.set(key, g);
    }
    g.occurrences++;
    if (f.commitSha === null) {
      g.inCurrentFiles = true;
    } else if (!g.commitSha || (f.commitDate && g.commitDate && f.commitDate < g.commitDate)) {
      g.commitSha = f.commitSha;
      g.author = f.author;
      g.commitDate = f.commitDate;
    }
  }
  return [...groups.values()];
}

export function renderSecretGroup(g: SecretGroup): string[] {
  const lines = [
    `    ${chalk.red('●')} ${chalk.bold(g.filePath)}  ${chalk.dim('·')}  ${chalk.red(g.type.toUpperCase())}  ${chalk.dim('·')}  ${chalk.yellow(g.maskedValue)}`,
  ];
  const where: string[] = [];
  if (g.commitSha) {
    where.push(
      `in git history since ${g.commitSha.slice(0, 7)}` +
        (g.author ? ` (${g.author}${g.commitDate ? `, ${g.commitDate.slice(0, 10)}` : ''})` : ''),
    );
  }
  if (g.inCurrentFiles) where.push('still in current files');
  lines.push(chalk.dim(`      ${where.join(' · ') || 'found'}`));
  return lines;
}

// ─── Dependencies ─────────────────────────────────────────────────────────────

function countBySeverity(findings: { severity: Severity }[]): string {
  const parts = SEVERITIES.filter((s) => findings.some((f) => f.severity === s)).map((s) =>
    sevColor(s)(`${findings.filter((f) => f.severity === s).length} ${s}`),
  );
  return parts.join(chalk.dim(' · '));
}

const worst = (fs: DependencyFinding[]): Severity =>
  fs.reduce<Severity>((w, f) => (rank(f.severity) < rank(w) ? f.severity : w), 'info');

const isGeneric = (f: DependencyFinding): boolean => /^Vulnerable dependency range/i.test(f.description);

function shorten(text: string, max: number): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 1) + '…' : t;
}

interface FixGroup {
  label: string;
  findings: DependencyFinding[];
  breaking: boolean;
}

/** Groups CVE findings by the single action that resolves them. */
export function groupFixes(cves: DependencyFinding[]): { auto: DependencyFinding[]; updates: FixGroup[]; manual: DependencyFinding[] } {
  const auto: DependencyFinding[] = [];
  const manual: DependencyFinding[] = [];
  const updates = new Map<string, FixGroup>();

  for (const f of cves) {
    const m = f.remediation.match(/^Update to (\S+) \((major upgrade|major|minor|patch)\)/i);
    if (m) {
      const g = updates.get(m[1]!) ?? { label: m[1]!, findings: [], breaking: /major/i.test(m[2]!) };
      g.findings.push(f);
      updates.set(m[1]!, g);
    } else if (/npm audit fix/i.test(f.remediation)) {
      auto.push(f);
    } else {
      manual.push(f);
    }
  }

  const sorted = [...updates.values()].sort(
    (a, b) => rank(worst(a.findings)) - rank(worst(b.findings)) || b.findings.length - a.findings.length,
  );
  return { auto, updates: sorted, manual };
}

function renderFullDep(f: DependencyFinding): string[] {
  const label =
    f.findingType === 'malicious-script' ? 'MALICIOUS SCRIPT' : f.findingType === 'typosquat' ? 'TYPOSQUAT' : 'SUPPLY CHAIN';
  return [
    `    ${badge(f.severity)} ${chalk.bold(f.packageName)}${f.version ? chalk.dim('@' + f.version) : ''}  ${chalk.dim('·')}  ${label}`,
    chalk.dim(`      ${shorten(f.description.split('\n')[0] ?? '', 110)}`),
    `      ${chalk.yellow('Fix:')} ${shorten(f.remediation, 110)}`,
  ];
}

export function renderDeps(repo: RepoReport): string[] {
  const deps = repo.deps!;
  const findings = deps.findings;
  const lines: string[] = [];

  const cves = findings.filter((f) => f.findingType === 'cve');
  const threats = findings.filter((f) => f.findingType !== 'cve');

  lines.push(
    `  ${chalk.bold('📦 Dependencies')}  ${findings.length} issue${findings.length === 1 ? '' : 's'}` +
      `  ${chalk.dim('(' + deps.packageCount + ' packages scanned)')}`,
  );
  lines.push(`     ${countBySeverity(findings)}`);

  // Malicious scripts / typosquats are rare and urgent: always shown in full.
  if (threats.length > 0) {
    lines.push('', chalk.bold.red('     ⚠ Possible supply-chain attack:'));
    for (const f of threats) lines.push(...renderFullDep(f));
  }

  if (cves.length > 0) {
    const { auto, updates, manual } = groupFixes(cves);
    lines.push('', chalk.bold('     How to fix:'));

    if (auto.length > 0) {
      lines.push(
        `       ${chalk.green('▸')} Run ${chalk.cyan('npm audit fix')}  ${chalk.dim('→')} resolves ${auto.length} issue${auto.length === 1 ? '' : 's'} ${chalk.dim('(' + countBySeverity(auto).replace(/\u001b\[[0-9;]*m/g, '') + ')')}`,
      );
    }
    for (const g of updates.slice(0, MAX_FIX_GROUPS)) {
      const names = [...new Set(g.findings.map((f) => f.packageName))];
      lines.push(
        `       ${chalk.green('▸')} Update to ${chalk.cyan(g.label)}${g.breaking ? chalk.yellow(' (breaking change — test after upgrading)') : ''}` +
          `  ${chalk.dim('→')} resolves ${g.findings.length} issue${g.findings.length === 1 ? '' : 's'}`,
      );
      lines.push(chalk.dim(`          ${shorten(names.slice(0, 5).join(', ') + (names.length > 5 ? `, +${names.length - 5} more` : ''), 100)}`));
    }
    if (updates.length > MAX_FIX_GROUPS) {
      lines.push(chalk.dim(`       … and ${updates.length - MAX_FIX_GROUPS} more upgrade(s)`));
    }
    if (manual.length > 0) {
      lines.push(`       ${chalk.green('▸')} ${manual.length} issue${manual.length === 1 ? '' : 's'} need manual review`);
    }

    const top = [...cves]
      .filter((f) => !isGeneric(f))
      .sort((a, b) => rank(a.severity) - rank(b.severity))
      .slice(0, MAX_TOP_ISSUES);
    if (top.length > 0) {
      lines.push('', chalk.bold('     Most serious:'));
      for (const f of top) {
        lines.push(`       ${badge(f.severity)} ${chalk.bold(f.packageName)}  ${chalk.dim(shorten(f.description, 80))}`);
      }
    }
  }
  return lines;
}

// ─── Report ───────────────────────────────────────────────────────────────────

function repoCounts(repo: RepoReport): { secrets: number; deps: DependencyFinding[] } {
  return {
    secrets: groupSecrets(repo.secrets?.findings ?? []).length,
    deps: repo.deps?.findings ?? [],
  };
}

export function renderCompactReport(report: ScanReport): string {
  const lines: string[] = [];
  const bar = '─'.repeat(62);

  lines.push(chalk.bold.cyan('\n╔══════════════════════════════════════════════════════════╗'));
  lines.push(chalk.bold.cyan('║           REPO GUARDIAN — SECURITY SCAN REPORT           ║'));
  lines.push(chalk.bold.cyan('╚══════════════════════════════════════════════════════════╝'));

  let totalSecrets = 0;
  let totalDeps = 0;
  let reposWithIssues = 0;
  let criticalDeps = 0;
  let hasAutoFix = false;
  const clean: string[] = [];

  for (const repo of report.repos) {
    const { secrets, deps } = repoCounts(repo);
    totalSecrets += secrets;
    totalDeps += deps.length;
    criticalDeps += deps.filter((d) => d.severity === 'critical').length;
    if (deps.some((d) => d.findingType === 'cve' && /npm audit fix/i.test(d.remediation))) hasAutoFix = true;

    if (secrets === 0 && deps.length === 0) {
      clean.push(repo.repoFullName);
      continue;
    }
    reposWithIssues++;

    lines.push('', chalk.cyan(bar));
    lines.push(`  ${chalk.bold.white(repo.repoFullName)}  ${chalk.dim(repo.htmlUrl)}`);
    lines.push(chalk.cyan(bar));

    if (repo.secrets) {
      const groups = groupSecrets(repo.secrets.findings).sort(
        (a, b) => Number(b.inCurrentFiles) - Number(a.inCurrentFiles),
      );
      if (groups.length === 0) {
        lines.push(`  ${chalk.green('🔑 Secrets')}  No secrets found`);
      } else {
        lines.push(`  ${chalk.bold.red('🔑 Secrets')}  ${groups.length} found ${chalk.dim('(values masked)')}`);
        for (const g of groups.slice(0, MAX_SECRET_GROUPS)) lines.push(...renderSecretGroup(g));
        if (groups.length > MAX_SECRET_GROUPS) {
          lines.push(chalk.dim(`    … and ${groups.length - MAX_SECRET_GROUPS} more (use --details to list all)`));
        }
        lines.push(chalk.dim(`    Fix: rotate these credentials, then run: repo-guardian clean ${repo.repoFullName}`));
      }
      lines.push('');
    }

    if (repo.deps) {
      if (!repo.deps.manifestFound) {
        lines.push(chalk.dim('  📦 Dependencies  no package.json found'));
      } else if (deps.length === 0) {
        lines.push(`  ${chalk.green('📦 Dependencies')}  Clean (${repo.deps.packageCount} packages scanned)`);
      } else {
        lines.push(...renderDeps(repo));
      }
    }
  }

  if (clean.length > 0) {
    lines.push('', chalk.cyan(bar));
    const parts = [report.repos.some((r) => r.secrets) ? 'No secrets found' : '', report.repos.some((r) => r.deps) ? 'dependencies clean' : ''].filter(Boolean);
    lines.push(`  ${chalk.green('✅')} ${clean.length} repo${clean.length === 1 ? '' : 's'}: ${parts.join(' · ')}`);
    lines.push(chalk.dim(`     ${shorten(clean.join(', '), 200)}`));
  }

  if (totalSecrets > 0) {
    lines.push(
      chalk.bold.red(
        '\n⚠️  IMPORTANT: Cleaning history does NOT undo exposure.\n' +
          '   Any credential found in git history should be considered compromised.\n' +
          '   Rotate it at your provider console NOW, before anything else.',
      ),
    );
  }

  lines.push('', chalk.bold.cyan(bar));
  if (totalSecrets === 0 && totalDeps === 0) {
    lines.push(chalk.bold.green('  ✅ All repos clean — no security findings detected.\n'));
  } else {
    const bits: string[] = [];
    if (totalSecrets > 0) bits.push(chalk.red(`${totalSecrets} secret${totalSecrets === 1 ? '' : 's'}`));
    if (totalDeps > 0) {
      bits.push(
        `${totalDeps} dependency issue${totalDeps === 1 ? '' : 's'}` + (criticalDeps > 0 ? chalk.bold.red(` (${criticalDeps} critical)`) : ''),
      );
    }
    lines.push(
      `  ${chalk.bold('Summary:')} ${bits.join(chalk.dim('  ·  '))} ${chalk.dim(`in ${reposWithIssues} of ${report.totalRepos} repo(s)`)}`,
    );
    lines.push(chalk.dim('  Next steps:'));
    if (totalSecrets > 0) lines.push(chalk.dim('    • repo-guardian clean <repo>        remove secrets from git history'));
    if (hasAutoFix) lines.push(chalk.dim('    • npm audit fix                      run in the repo to auto-fix dependencies'));
    lines.push(chalk.dim('    • repo-guardian init-prevention      stop new secrets being committed'));
    lines.push(chalk.dim('    • repo-guardian scan ... --details   show every finding in full\n'));
  }
  return lines.join('\n');
}
