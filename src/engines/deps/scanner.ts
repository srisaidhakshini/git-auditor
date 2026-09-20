/**
 * scanner.ts — Dependency and supply chain malware scanner.
 *
 * Implements:
 * 1. npm audit for known CVEs
 * 2. Supply-chain heuristic analysis (malicious install scripts, suspicious commands)
 * 3. Typosquat detection against popular npm ecosystem packages
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runCommand } from '../../utils/shell.js';
import { logger } from '../../utils/logger.js';
import type { DependencyFinding, DependencyScanResult } from './types.js';
import type { Severity } from '../../report/types.js';

// Top high-profile npm packages commonly targeted by typosquatters
const POPULAR_PACKAGES = [
  'lodash',
  'express',
  'react',
  'react-dom',
  'axios',
  'chalk',
  'commander',
  'inquirer',
  'typescript',
  'next',
  'vue',
  'webpack',
  'dotenv',
  'cross-env',
  'colors',
  'uuid',
  'moment',
  'rxjs',
  'tslib',
  'glob',
  'async',
  'body-parser',
  'mongoose',
  'debug',
  'request',
  'socket.io',
  'postcss',
  'eslint',
  'prettier',
];

/**
 * Calculates the Levenshtein distance between two strings.
 */
function levenshtein(a: string, b: string): number {
  const an = a.length;
  const bn = b.length;
  if (an === 0) return bn;
  if (bn === 0) return an;

  const matrix: number[][] = [];
  for (let i = 0; i <= bn; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= an; j++) {
    matrix[0]![j] = j;
  }

  for (let i = 1; i <= bn; i++) {
    for (let j = 1; j <= an; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i]![j] = matrix[i - 1]![j - 1]!;
      } else {
        matrix[i]![j] = Math.min(
          matrix[i - 1]![j - 1]! + 1, // substitution
          matrix[i]![j - 1]! + 1,     // insertion
          matrix[i - 1]![j]! + 1,     // deletion
        );
      }
    }
  }

  return matrix[bn]![an]!;
}

/**
 * Checks for suspicious lifecycle scripts in package.json.
 */
function analyzeScripts(scripts: Record<string, string>): DependencyFinding[] {
  const findings: DependencyFinding[] = [];
  const dangerousHooks = ['preinstall', 'postinstall', 'install', 'prepublish', 'prepublishOnly'];

  const suspiciousPatterns: Array<{ pattern: RegExp; desc: string; severity: Severity }> = [
    {
      pattern: /(curl|wget|fetch|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+.*(\||>|eval|bash|sh|cmd|powershell)/i,
      desc: 'Downloads remote script and immediately executes it via shell pipeline',
      severity: 'critical',
    },
    {
      pattern: /base64\s+(-d|--decode)|atob\(|Buffer\.from\(.*'base64'\)|\[Convert\]::FromBase64String/i,
      desc: 'Decodes obfuscated base64 payload during script execution',
      severity: 'critical',
    },
    {
      pattern: /cat\s+~?\/?(\.ssh|\.aws|\.gnupg|\.env)|Get-Content.*(\.ssh|\.aws|\.env)/i,
      desc: 'Attempts to read sensitive user credentials/keys from disk',
      severity: 'critical',
    },
    {
      pattern: /(https?:\/\/(?:pastebin|discord(?:app)?\.com\/api\/webhooks|webhook\.site|ngrok\.io|bit\.ly)[^\s"']+)/i,
      desc: 'Contains hardcoded external webhook or untrusted URL commonly used for data exfiltration',
      severity: 'high',
    },
    {
      pattern: /eval\(|Function\(/i,
      desc: 'Uses dynamic code evaluation inside package script',
      severity: 'high',
    },
    {
      pattern: /node\s+-e\s+["'].*(net\.connect|http\.request|child_process|execSync|spawnSync).*["']/i,
      desc: 'Executes inline Node.js snippet performing network or process spawning',
      severity: 'high',
    },
  ];

  for (const [hookName, command] of Object.entries(scripts)) {
    const isLifecycle = dangerousHooks.includes(hookName);

    for (const rule of suspiciousPatterns) {
      if (rule.pattern.test(command)) {
        findings.push({
          id: `malicious-script-${hookName}-${findings.length + 1}`,
          packageName: 'package.json (scripts)',
          severity: rule.severity,
          findingType: 'malicious-script',
          title: `Suspicious lifecycle script detected in "${hookName}"`,
          description: `${rule.desc}.\nCommand: "${command}"`,
          remediation: `Inspect and remove malicious/unvetted commands from "${hookName}" script in package.json.`,
          details: {
            hook: hookName,
            command,
            isLifecycleHook: isLifecycle,
          },
        });
      }
    }
  }

  return findings;
}

/**
 * Checks declared dependency names for typosquats against popular npm packages.
 */
function analyzeTyposquats(dependencies: Record<string, string>): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

  for (const [pkgName, version] of Object.entries(dependencies)) {
    // Ignore exact matches with legitimate packages
    if (POPULAR_PACKAGES.includes(pkgName.toLowerCase())) {
      continue;
    }

    for (const popular of POPULAR_PACKAGES) {
      const distance = levenshtein(pkgName.toLowerCase(), popular.toLowerCase());
      // Flag if distance is 1 (e.g. "cross-env.js" or "lod-ash" or "exppress") and length >= 4
      if (distance === 1 && popular.length >= 4) {
        findings.push({
          id: `typosquat-${pkgName}`,
          packageName: pkgName,
          version,
          severity: 'critical',
          findingType: 'typosquat',
          title: `Possible typosquatting package "${pkgName}"`,
          description: `The package name "${pkgName}" is suspiciously similar (edit distance 1) to the popular package "${popular}". Typosquats frequently deliver malware or infostealers.`,
          remediation: `Verify if "${pkgName}" is legitimate. If you intended to use "${popular}", uninstall "${pkgName}" and install "${popular}".`,
          details: {
            similarTo: popular,
            editDistance: distance,
          },
        });
      }
    }
  }

  return findings;
}

/**
 * Runs `npm audit --json` inside the repository directory.
 */
async function runNpmAudit(repoPath: string, timeoutMs: number = 30000): Promise<DependencyFinding[]> {
  const findings: DependencyFinding[] = [];

  try {
    const res = await runCommand('npm', ['audit', '--json'], {
      cwd: repoPath,
      timeoutMs,
    });

    if (!res.stdout) {
      return findings;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(res.stdout);
    } catch {
      return findings;
    }

    if (parsed.vulnerabilities) {
      // npm 7+ format
      for (const [name, vuln] of Object.entries<any>(parsed.vulnerabilities)) {
        const severity: Severity =
          vuln.severity === 'critical'
            ? 'critical'
            : vuln.severity === 'high'
              ? 'high'
              : vuln.severity === 'moderate'
                ? 'medium'
                : 'low';

        const via = Array.isArray(vuln.via) ? vuln.via : [];
        const advisory = via.find((v: any) => typeof v === 'object' && v !== null);
        const cveId = advisory?.cve ?? (advisory?.url?.includes('GHSA-') ? advisory.url.split('/').pop() : undefined);

        findings.push({
          id: `cve-${name}-${vuln.severity}`,
          packageName: name,
          version: vuln.range ?? vuln.version,
          severity,
          findingType: 'cve',
          title: `Known vulnerability in ${name} (${vuln.severity})`,
          description: advisory?.title ?? `Vulnerable dependency range: ${vuln.range || name}`,
          remediation: vuln.fixAvailable
            ? typeof vuln.fixAvailable === 'object'
              ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version} (${vuln.fixAvailable.isSemVerMajor ? 'major upgrade' : 'patch'})`
              : 'Run npm audit fix or update package version in package.json'
            : 'Check package advisory for mitigation or upgrade path',
          cveId,
          advisoryUrl: advisory?.url,
          details: {
            isDirect: vuln.isDirect,
            effects: vuln.effects,
          },
        });
      }
    } else if (parsed.advisories) {
      // npm 6 format
      for (const adv of Object.values<any>(parsed.advisories)) {
        const severity: Severity =
          adv.severity === 'critical'
            ? 'critical'
            : adv.severity === 'high'
              ? 'high'
              : adv.severity === 'moderate'
                ? 'medium'
                : 'low';

        findings.push({
          id: `cve-${adv.id}`,
          packageName: adv.module_name,
          version: adv.vulnerable_versions,
          severity,
          findingType: 'cve',
          title: adv.title,
          description: adv.overview ?? adv.title,
          remediation: adv.recommendation ?? 'Upgrade to patched version',
          cveId: adv.cves?.[0],
          advisoryUrl: adv.url,
        });
      }
    }
  } catch (err) {
    logger.debug(`npm audit failed or timed out: ${err instanceof Error ? err.message : String(err)}`);
  }

  return findings;
}

/**
 * Scans a repository for dependency vulnerabilities and supply-chain malware.
 */
export async function scanDependencies(
  repoPath: string,
  repoFullName: string,
  timeoutMs: number = 30000,
): Promise<DependencyScanResult> {
  const packageJsonPath = join(repoPath, 'package.json');
  const now = new Date().toISOString();

  if (!existsSync(packageJsonPath)) {
    return {
      repoFullName,
      manifestFound: false,
      packageCount: 0,
      findings: [],
      scannedAt: now,
    };
  }

  let pkgJson: any;
  try {
    pkgJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  } catch (err) {
    return {
      repoFullName,
      manifestFound: true,
      manifestPath: 'package.json',
      packageCount: 0,
      findings: [],
      scannedAt: now,
      error: `Failed to parse package.json: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const dependencies: Record<string, string> = {
    ...(pkgJson.dependencies || {}),
    ...(pkgJson.devDependencies || {}),
    ...(pkgJson.optionalDependencies || {}),
  };

  const scripts: Record<string, string> = pkgJson.scripts || {};
  const packageCount = Object.keys(dependencies).length;

  const findings: DependencyFinding[] = [];

  // 1. Analyze scripts for malicious hooks
  findings.push(...analyzeScripts(scripts));

  // 2. Analyze package names for typosquats
  findings.push(...analyzeTyposquats(dependencies));

  // 3. Run npm audit for known CVEs
  const auditFindings = await runNpmAudit(repoPath, timeoutMs);
  findings.push(...auditFindings);

  return {
    repoFullName,
    manifestFound: true,
    manifestPath: 'package.json',
    packageCount,
    findings,
    scannedAt: now,
  };
}
