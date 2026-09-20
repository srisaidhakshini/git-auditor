/**
 * formatter.ts — Terminal and HTML report renderers.
 *
 * Produces human-readable, colour-coded summaries of findings
 * grouped by: repo → engine → severity.
 *
 * SAFETY: Only masked values from SecretFinding.maskedValue are printed.
 */

import chalk, { type ChalkInstance } from 'chalk';
import type { ScanReport, RepoReport, Severity } from './types.js';
import type { SecretFinding } from '../engines/secrets/types.js';
import type { DependencyFinding } from '../engines/deps/types.js';

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

function secretSeverityColor(type: SecretFinding['secretType']): ChalkInstance {
  const critical = ['aws-access-key', 'aws-secret-key', 'private-key', 'github-token'];
  const high = ['stripe-key', 'sendgrid-key', 'twilio-key', 'google-api-key'];
  if (critical.includes(type)) return c.critical;
  if (high.includes(type)) return c.high;
  return c.medium;
}

function depSeverityColor(severity: Severity): ChalkInstance {
  switch (severity) {
    case 'critical':
      return c.critical;
    case 'high':
      return c.high;
    case 'medium':
      return c.medium;
    case 'low':
      return c.low;
    default:
      return c.info;
  }
}

// ─── Rotation reminder (mandatory per PRD §5) ─────────────────────────────────

const ROTATION_REMINDER = chalk.bold.red(
  '\n⚠️  IMPORTANT: Cleaning history does NOT undo exposure.\n' +
    '   Any credential found in git history should be considered compromised.\n' +
    '   Rotate it at your provider console NOW, before anything else.\n',
);

// ─── Secret findings block ───────────────────────────────────────────────────

function renderSecretFinding(finding: SecretFinding, index: number): string {
  const color = secretSeverityColor(finding.secretType);
  const lines: string[] = [];

  lines.push(
    color(`    [S${index + 1}] ${finding.secretType.toUpperCase()}`) +
      c.dim(` (rule: ${finding.ruleId})`),
  );
  lines.push(`        ${c.label('File:')}   ${c.value(finding.filePath)}`);

  if (finding.commitSha) {
    lines.push(
      `        ${c.label('Commit:')} ${c.value(finding.commitSha.slice(0, 12))}` +
        (finding.author ? c.dim(` by ${finding.author}`) : '') +
        (finding.commitDate ? c.dim(` on ${finding.commitDate.slice(0, 10)}`) : ''),
    );
  }

  if (finding.lineNumber) {
    lines.push(`        ${c.label('Line:')}   ${c.value(String(finding.lineNumber))}`);
  }

  lines.push(`        ${c.label('Value:')}  ${c.warn(finding.maskedValue)}`);
  lines.push('');

  return lines.join('\n');
}

// ─── Dependency findings block ────────────────────────────────────────────────

function renderDepFinding(finding: DependencyFinding, index: number): string {
  const color = depSeverityColor(finding.severity);
  const lines: string[] = [];

  const typeLabel =
    finding.findingType === 'cve'
      ? 'CVE VULNERABILITY'
      : finding.findingType === 'malicious-script'
        ? 'MALICIOUS SCRIPT'
        : finding.findingType === 'typosquat'
          ? 'TYPOSQUAT RISK'
          : 'SUPPLY CHAIN RISK';

  lines.push(
    color(`    [D${index + 1}] [${finding.severity.toUpperCase()}] ${typeLabel}: ${finding.packageName}`) +
      (finding.version ? c.dim(`@${finding.version}`) : ''),
  );
  lines.push(`        ${c.label('Title:')}       ${c.value(finding.title)}`);
  lines.push(`        ${c.label('Description:')} ${c.dim(finding.description)}`);
  lines.push(`        ${c.label('Remediation:')} ${c.warn(finding.remediation)}`);

  if (finding.advisoryUrl) {
    lines.push(`        ${c.label('Advisory:')}    ${c.dim(finding.advisoryUrl)}`);
  }
  lines.push('');

  return lines.join('\n');
}

// ─── Per-repo block ───────────────────────────────────────────────────────────

function renderRepo(repo: RepoReport): string {
  const lines: string[] = [];
  const secretFindings = repo.secrets?.findings ?? [];
  const depFindings = repo.deps?.findings ?? [];

  const bar = '─'.repeat(60);
  lines.push(c.heading(`\n${bar}`));
  lines.push(c.repo(`  📦 ${repo.repoFullName}`) + c.dim(`  ${repo.htmlUrl}`));
  lines.push(c.heading(bar));

  // Secrets section
  if (repo.secrets) {
    if (secretFindings.length === 0) {
      lines.push(c.success('  🔑 Secrets: No secrets found (clean)'));
    } else {
      lines.push(
        c.critical(`  🔑 Secrets: 🔴 ${secretFindings.length} secret(s) found`) +
          c.dim(' — masked values shown below:'),
      );
      lines.push('');
      for (let i = 0; i < secretFindings.length; i++) {
        lines.push(renderSecretFinding(secretFindings[i]!, i));
      }
    }
  }

  // Dependencies section
  if (repo.deps) {
    if (!repo.deps.manifestFound) {
      lines.push(c.dim('  📦 Dependencies: No package.json manifest found'));
    } else if (depFindings.length === 0) {
      lines.push(c.success(`  📦 Dependencies: Clean (${repo.deps.packageCount} packages scanned)`));
    } else {
      lines.push(
        c.critical(`  📦 Dependencies: ⚠️  ${depFindings.length} issue(s) detected`) +
          c.dim(` (${repo.deps.packageCount} packages scanned):`),
      );
      lines.push('');
      for (let i = 0; i < depFindings.length; i++) {
        lines.push(renderDepFinding(depFindings[i]!, i));
      }
    }
  }

  // Repo clean state
  if (secretFindings.length === 0 && depFindings.length === 0) {
    lines.push(c.success('  ✅ Repository is secure and clean.\n'));
  }

  return lines.join('\n');
}

// ─── Terminal Renderer ────────────────────────────────────────────────────────

export function renderTerminalReport(report: ScanReport): string {
  const lines: string[] = [];

  lines.push(c.heading('\n╔══════════════════════════════════════════════════════════╗'));
  lines.push(c.heading('║           REPO GUARDIAN — SECURITY SCAN REPORT           ║'));
  lines.push(c.heading('╚══════════════════════════════════════════════════════════╝'));
  lines.push(c.dim(`  Generated: ${report.generatedAt}`));
  lines.push(
    c.dim(`  Repos scanned: ${report.totalRepos}  |  Total findings: ${report.totalFindings}`),
  );

  let hasSecrets = false;

  for (const repo of report.repos) {
    lines.push(renderRepo(repo));
    if ((repo.secrets?.findings?.length ?? 0) > 0) {
      hasSecrets = true;
    }
  }

  // Mandatory rotation reminder if secrets were found anywhere
  if (hasSecrets) {
    lines.push(ROTATION_REMINDER);
  }

  // Summary footer
  lines.push(c.heading('─'.repeat(62)));
  if (report.totalFindings === 0) {
    lines.push(c.success('  ✅ All repos clean — no security findings detected.\n'));
  } else {
    lines.push(
      c.critical(
        `  ⚠️  ${report.totalFindings} security finding(s) detected across ${report.totalRepos} repo(s).`,
      ),
    );
    if (hasSecrets) {
      lines.push(c.warn('  • Secrets: Run `repo-guardian clean <repo>` to rewrite git history safely.'));
    }
    lines.push(c.warn('  • Prevention: Run `repo-guardian init-prevention` to install guardrails.\n'));
  }

  return lines.join('\n');
}

/**
 * Renders the report as compact, machine-readable JSON.
 */
export function renderJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── HTML Renderer ────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderHtmlReport(report: ScanReport): string {
  let totalSecrets = 0;
  let totalDeps = 0;

  for (const r of report.repos) {
    totalSecrets += r.secrets?.findings?.length ?? 0;
    totalDeps += r.deps?.findings?.length ?? 0;
  }

  const repoCardsHtml = report.repos
    .map((repo) => {
      const secretFindings = repo.secrets?.findings ?? [];
      const depFindings = repo.deps?.findings ?? [];
      const repoTotal = secretFindings.length + depFindings.length;

      const statusBadge =
        repoTotal === 0
          ? `<span class="badge badge-success">Clean</span>`
          : `<span class="badge badge-danger">${repoTotal} Finding${repoTotal > 1 ? 's' : ''}</span>`;

      const secretsHtml = secretFindings.length
        ? secretFindings
            .map(
              (f, i) => `
          <div class="finding-item finding-secret">
            <div class="finding-header">
              <span class="finding-badge badge-secret">[S${i + 1}] ${escapeHtml(f.secretType.toUpperCase())}</span>
              <span class="finding-rule">Rule: ${escapeHtml(f.ruleId)}</span>
            </div>
            <div class="finding-meta">
              <div><strong>File:</strong> <code>${escapeHtml(f.filePath)}</code></div>
              ${f.commitSha ? `<div><strong>Commit:</strong> <code>${escapeHtml(f.commitSha.slice(0, 10))}</code> (${escapeHtml(f.author || 'unknown')})</div>` : ''}
              ${f.lineNumber ? `<div><strong>Line:</strong> ${f.lineNumber}</div>` : ''}
              <div><strong>Masked Value:</strong> <span class="masked-value">${escapeHtml(f.maskedValue)}</span></div>
            </div>
          </div>`,
            )
            .join('')
        : '<p class="clean-note">✅ No leaked secrets detected in history.</p>';

      const depsHtml = depFindings.length
        ? depFindings
            .map(
              (d, i) => `
          <div class="finding-item finding-dep">
            <div class="finding-header">
              <span class="finding-badge badge-${d.severity}">[${d.severity.toUpperCase()}] ${escapeHtml(d.findingType.toUpperCase())}: ${escapeHtml(d.packageName)}</span>
              ${d.version ? `<span class="finding-version">v${escapeHtml(d.version)}</span>` : ''}
            </div>
            <div class="finding-meta">
              <div><strong>Title:</strong> ${escapeHtml(d.title)}</div>
              <div><strong>Description:</strong> ${escapeHtml(d.description)}</div>
              <div class="remediation-box"><strong>Remediation:</strong> ${escapeHtml(d.remediation)}</div>
              ${d.advisoryUrl ? `<div><a href="${escapeHtml(d.advisoryUrl)}" target="_blank" rel="noopener" class="advisory-link">View Security Advisory &rarr;</a></div>` : ''}
            </div>
          </div>`,
            )
            .join('')
        : `<p class="clean-note">${repo.deps?.manifestFound ? '✅ No malicious packages or high-risk CVEs detected.' : 'ℹ️ No package.json manifest found.'}</p>`;

      return `
      <section class="repo-card">
        <header class="repo-header">
          <div>
            <h2 class="repo-title">📦 <a href="${escapeHtml(repo.htmlUrl)}" target="_blank" rel="noopener">${escapeHtml(repo.repoFullName)}</a></h2>
          </div>
          <div>${statusBadge}</div>
        </header>
        <div class="repo-body">
          <div class="section-block">
            <h3>🔑 Secret Scanning Findings (${secretFindings.length})</h3>
            ${secretsHtml}
          </div>
          <div class="section-block">
            <h3>🛡️ Dependency & Malware Findings (${depFindings.length})</h3>
            ${depsHtml}
          </div>
        </div>
      </section>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Repo Guardian — Security Scan Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --danger: #f85149;
      --warn: #d29922;
      --success: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1rem;
    }
    .container { max-width: 1080px; margin: 0 auto; }
    header.main-header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { color: var(--text-bright); font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }
    .subtitle { color: #8b949e; font-size: 0.9rem; margin-top: 0.3rem; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }
    .stat-number { font-size: 2rem; font-weight: bold; color: var(--text-bright); }
    .stat-number.danger { color: var(--danger); }
    .stat-number.success { color: var(--success); }
    .stat-label { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .alert-banner {
      background: rgba(248, 81, 73, 0.15);
      border: 1px solid var(--danger);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 2rem;
      color: #ff7b72;
    }
    .repo-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }
    .repo-header {
      background: rgba(255, 255, 255, 0.03);
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .repo-title { font-size: 1.15rem; }
    .repo-title a { color: var(--accent); text-decoration: none; }
    .repo-title a:hover { text-decoration: underline; }
    .repo-body { padding: 1.25rem; }
    .section-block { margin-bottom: 1.5rem; }
    .section-block h3 { font-size: 1rem; color: var(--text-bright); margin-bottom: 0.75rem; }
    .finding-item {
      background: rgba(0,0,0,0.25);
      border-left: 4px solid var(--danger);
      border-radius: 4px;
      padding: 0.85rem;
      margin-bottom: 0.75rem;
    }
    .finding-item.finding-dep { border-left-color: var(--warn); }
    .finding-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); }
    .badge-danger { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
    .badge-critical { background: rgba(248, 81, 73, 0.3); color: var(--danger); }
    .badge-high { background: rgba(210, 153, 34, 0.3); color: var(--warn); }
    .badge-medium { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
    .finding-badge { font-weight: bold; font-size: 0.85rem; }
    .badge-secret { color: var(--danger); }
    .finding-rule, .finding-version { font-size: 0.8rem; color: #8b949e; }
    .finding-meta { font-size: 0.88rem; display: flex; flex-direction: column; gap: 0.3rem; }
    .masked-value { color: var(--warn); font-family: monospace; }
    code { background: rgba(255,255,255,0.08); padding: 0.1rem 0.3rem; border-radius: 3px; font-family: monospace; }
    .remediation-box {
      margin-top: 0.4rem;
      padding: 0.5rem;
      background: rgba(210, 153, 34, 0.1);
      border-radius: 4px;
      color: #e3b341;
    }
    .advisory-link { color: var(--accent); text-decoration: none; font-size: 0.85rem; }
    .clean-note { color: #8b949e; font-size: 0.88rem; font-style: italic; }
    footer { text-align: center; font-size: 0.8rem; color: #8b949e; margin-top: 3rem; }
  </style>
</head>
<body>
  <div class="container">
    <header class="main-header">
      <h1>🛡️ Repo Guardian — Security Report</h1>
      <p class="subtitle">Generated on ${escapeHtml(report.generatedAt)}</p>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-number">${report.totalRepos}</div>
        <div class="stat-label">Repositories</div>
      </div>
      <div class="stat-card">
        <div class="stat-number ${report.totalFindings > 0 ? 'danger' : 'success'}">${report.totalFindings}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-number ${totalSecrets > 0 ? 'danger' : 'success'}">${totalSecrets}</div>
        <div class="stat-label">Secrets Leaked</div>
      </div>
      <div class="stat-card">
        <div class="stat-number ${totalDeps > 0 ? 'danger' : 'success'}">${totalDeps}</div>
        <div class="stat-label">Dependency Risks</div>
      </div>
    </div>

    ${
      totalSecrets > 0
        ? `<div class="alert-banner">
      <strong>⚠️ CRITICAL REMINDER:</strong> Cleaning git history does NOT undo exposure. Leaked credentials should be rotated immediately at provider consoles.
    </div>`
        : ''
    }

    ${repoCardsHtml}

    <footer>
      <p>Repo Guardian — Automated Security & Hygiene Agent</p>
    </footer>
  </div>
</body>
</html>`;
}
