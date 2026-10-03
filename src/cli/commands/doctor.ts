/**
 * doctor.ts — `repo-guardian doctor`: checks the environment and says how to fix gaps.
 */

import type { Command } from 'commander';
import chalk from 'chalk';
import { runCommand } from '../../utils/shell.js';
import { resolveGitHubToken } from '../../github/auth.js';

interface CheckResult {
  ok: boolean;
  detail: string;
  fix?: string;
}

interface Check {
  name: string;
  required: boolean;
  run: () => Promise<CheckResult>;
}

async function toolVersion(cmd: string, args: string[]): Promise<string | null> {
  try {
    const r = await runCommand(cmd, args);
    if (r.exitCode !== 0) return null;
    return (r.stdout || r.stderr).trim().split('\n')[0] ?? '';
  } catch {
    return null;
  }
}

const CHECKS: Check[] = [
  {
    name: 'Node.js >= 20',
    required: true,
    run: async () => {
      const major = parseInt(process.versions.node.split('.')[0] ?? '0', 10);
      return {
        ok: major >= 20,
        detail: `v${process.versions.node}`,
        fix: 'Install Node 20+ from https://nodejs.org',
      };
    },
  },
  {
    name: 'git',
    required: true,
    run: async () => {
      const v = await toolVersion('git', ['--version']);
      return { ok: v !== null, detail: v ?? 'not found', fix: 'Install git from https://git-scm.com' };
    },
  },
  {
    name: 'GitHub authentication',
    required: true,
    run: async () => {
      try {
        const a = await resolveGitHubToken();
        return { ok: true, detail: `via ${a.source}${a.user ? ` (${a.user})` : ''}` };
      } catch {
        return { ok: false, detail: 'not logged in', fix: 'Run: repo-guardian auth login' };
      }
    },
  },
  {
    name: 'gitleaks (better secret detection)',
    required: false,
    run: async () => {
      const v = await toolVersion('gitleaks', ['version']);
      return {
        ok: v !== null,
        detail: v ?? 'not found — built-in scanner will be used',
        fix: 'winget install gitleaks  |  brew install gitleaks',
      };
    },
  },
  {
    name: 'git-filter-repo (faster history rewrite)',
    required: false,
    run: async () => {
      const v = await toolVersion('git', ['filter-repo', '--version']);
      return {
        ok: v !== null,
        detail: v ?? 'not found — git filter-branch will be used',
        fix: 'pip install git-filter-repo',
      };
    },
  },
  {
    name: 'npm (dependency audit)',
    required: false,
    run: async () => {
      const v = await toolVersion('npm', ['--version']);
      return { ok: v !== null, detail: v ? `v${v}` : 'not found', fix: 'Comes with Node.js' };
    },
  },
  {
    name: 'ANTHROPIC_API_KEY (full AI chat)',
    required: false,
    run: async () => ({
      ok: Boolean(process.env['ANTHROPIC_API_KEY']),
      detail: process.env['ANTHROPIC_API_KEY'] ? 'set' : 'not set — chat uses the offline planner',
      fix: 'Set ANTHROPIC_API_KEY to enable Claude in `repo-guardian chat`',
    }),
  },
];

export async function runDoctor(): Promise<void> {
  console.log(chalk.bold.cyan('\n🩺 Repo Guardian doctor\n'));
  let requiredFailed = false;

  for (const check of CHECKS) {
    const res = await check.run();
    const icon = res.ok ? chalk.green('✓') : check.required ? chalk.red('✗') : chalk.yellow('!');
    console.log(`  ${icon} ${check.name}  ${chalk.dim(res.detail)}`);
    if (!res.ok && res.fix) console.log(chalk.dim(`      → ${res.fix}`));
    if (!res.ok && check.required) requiredFailed = true;
  }

  console.log(
    requiredFailed
      ? chalk.red('\nSome required checks failed. Fix them and run `repo-guardian doctor` again.\n')
      : chalk.green('\nYou are good to go. Try: repo-guardian scan\n'),
  );
  process.exit(requiredFailed ? 1 : 0);
}

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Check your setup (git, GitHub login, gitleaks, …) and show how to fix problems')
    .action(runDoctor);
}
