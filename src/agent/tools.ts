/**
 * tools.ts — Tool definitions and execution dispatchers for the Agent Loop.
 */

import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { AgentToolDefinition, AgentToolCall, AgentExecutionContext } from './types.js';
import { resolveGitHubToken } from '../github/auth.js';
import { listOwnedRepos, findRepo } from '../github/repos.js';
import { scanSecrets } from '../engines/secrets/scanner.js';
import { scanDependencies } from '../engines/deps/scanner.js';
import { createVerifiedBackup, dryRunRewrite, executeRewrite } from '../engines/secrets/rewriter.js';
import { pushRewrittenHistory } from '../engines/secrets/pusher.js';
import { patchGitignore } from '../engines/prevention/gitignore.js';
import { installPreCommitHook } from '../engines/prevention/hooks.js';
import { cloneRepo } from '../cli/commands/scan.js';
import { rmSync } from 'node:fs';

export const AGENT_TOOLS: AgentToolDefinition[] = [
  {
    name: 'list_repositories',
    description: 'Lists GitHub repositories owned by the authenticated user.',
    input_schema: {
      type: 'object',
      properties: {
        refresh: {
          type: 'boolean',
          description: 'Whether to force-refresh cached repository list.',
        },
      },
    },
  },
  {
    name: 'scan_secrets',
    description: 'Scans a GitHub repository git history for leaked credentials and secrets (API keys, tokens, .env files).',
    input_schema: {
      type: 'object',
      properties: {
        repo_name: {
          type: 'string',
          description: 'Repository name (e.g. "owner/repo" or "repo").',
        },
      },
      required: ['repo_name'],
    },
  },
  {
    name: 'scan_dependencies',
    description: 'Scans a repository dependencies for known CVEs, malicious install scripts, and typosquats.',
    input_schema: {
      type: 'object',
      properties: {
        repo_name: {
          type: 'string',
          description: 'Repository name (e.g. "owner/repo" or "repo").',
        },
      },
      required: ['repo_name'],
    },
  },
  {
    name: 'rewrite_history',
    description: 'Examines or excises sensitive files from git history using a verified backup and git filter-repo. Set dry_run=true to preview without modifying.',
    isDestructive: true,
    input_schema: {
      type: 'object',
      properties: {
        repo_name: {
          type: 'string',
          description: 'Repository name.',
        },
        patterns: {
          type: 'array',
          items: { type: 'string' },
          description: 'File patterns to purge (defaults to [".env", ".env.*", "*.pem", "*.key"]).',
        },
        dry_run: {
          type: 'boolean',
          description: 'If true, only previews affected commits without making changes.',
        },
      },
      required: ['repo_name'],
    },
  },
  {
    name: 'push_rewritten_history',
    description: 'Force-pushes rewritten git history to GitHub after checking branch protection. STRICTLY DESTRUCTIVE.',
    isDestructive: true,
    input_schema: {
      type: 'object',
      properties: {
        repo_name: {
          type: 'string',
          description: 'Repository name.',
        },
        branch: {
          type: 'string',
          description: 'Target branch to push.',
        },
      },
      required: ['repo_name'],
    },
  },
  {
    name: 'init_prevention',
    description: 'Sets up .gitignore guardrails and installs git pre-commit hooks to block future secret leaks.',
    input_schema: {
      type: 'object',
      properties: {
        target_path: {
          type: 'string',
          description: 'Local directory path (defaults to current working directory).',
        },
      },
    },
  },
];

/**
 * Executes a tool called by the agent.
 */
export async function executeAgentTool(
  toolCall: AgentToolCall,
  context: AgentExecutionContext,
): Promise<Record<string, unknown>> {
  switch (toolCall.name) {
    case 'list_repositories': {
      const auth = await resolveGitHubToken();
      const repos = await listOwnedRepos(auth);
      return {
        count: repos.length,
        repositories: repos.map((r) => ({
          name: r.name,
          fullName: r.fullName,
          private: r.private,
          defaultBranch: r.defaultBranch,
          htmlUrl: r.htmlUrl,
        })),
      };
    }

    case 'scan_secrets': {
      const auth = await resolveGitHubToken();
      const repoName = toolCall.input.repo_name as string;
      const repo = await findRepo(auth, repoName);
      const cloned = await cloneRepo(repo.cloneUrl, auth.token);

      try {
        const result = await scanSecrets(cloned, repo.fullName, 'full-history');
        return {
          repoFullName: repo.fullName,
          findingsCount: result.findings.length,
          findings: result.findings,
          rotationReminder: result.findings.length > 0 ? 'CRITICAL: Leaked secrets must be rotated at provider console!' : undefined,
        };
      } finally {
        rmSync(cloned, { recursive: true, force: true });
      }
    }

    case 'scan_dependencies': {
      const auth = await resolveGitHubToken();
      const repoName = toolCall.input.repo_name as string;
      const repo = await findRepo(auth, repoName);
      const cloned = await cloneRepo(repo.cloneUrl, auth.token);

      try {
        const result = await scanDependencies(cloned, repo.fullName);
        return {
          repoFullName: repo.fullName,
          manifestFound: result.manifestFound,
          packageCount: result.packageCount,
          findingsCount: result.findings.length,
          findings: result.findings,
        };
      } finally {
        rmSync(cloned, { recursive: true, force: true });
      }
    }

    case 'rewrite_history': {
      const auth = await resolveGitHubToken();
      const repoName = toolCall.input.repo_name as string;
      const patterns = (toolCall.input.patterns as string[]) || ['.env', '.env.*', '*.pem', '*.key'];
      const dryRun = toolCall.input.dry_run !== false; // default to dry run for safety

      const repo = await findRepo(auth, repoName);
      const cloned = await cloneRepo(repo.cloneUrl, auth.token);

      try {
        const dryRunResult = await dryRunRewrite(cloned, patterns);

        if (dryRun) {
          return {
            mode: 'dry-run',
            repoFullName: repo.fullName,
            totalCommitsToRewrite: dryRunResult.totalCommitsToRewrite,
            affectedCommits: dryRunResult.affectedCommits,
            targetPatterns: patterns,
          };
        }

        // Real execution
        const backup = await createVerifiedBackup(cloned);
        const rewriteResult = await executeRewrite(cloned, patterns, repo.fullName, backup.backupPath);

        return {
          mode: 'execute',
          success: rewriteResult.success,
          repoFullName: repo.fullName,
          backupPath: backup.backupPath,
          headShaBefore: rewriteResult.headShaBefore,
          headShaAfter: rewriteResult.headShaAfter,
          rotationReminder: 'IMPORTANT: Leaked credentials must be rotated at provider consoles!',
        };
      } finally {
        if (dryRun) {
          rmSync(cloned, { recursive: true, force: true });
        }
      }
    }

    case 'push_rewritten_history': {
      const repoName = toolCall.input.repo_name as string;
      const branch = (toolCall.input.branch as string) || 'main';

      return {
        message: `Force push for ${repoName}:${branch} requires separate interactive terminal confirmation via CLI prompt.`,
      };
    }

    case 'init_prevention': {
      const targetPath = resolve((toolCall.input.target_path as string) || context.workingDir);
      if (!existsSync(join(targetPath, '.git'))) {
        return { error: `${targetPath} is not a git repository (no .git folder found).` };
      }
      const gitignore = patchGitignore(targetPath);
      const hook = installPreCommitHook(targetPath);

      return {
        targetPath,
        gitignoreModified: gitignore.modified,
        addedIgnorePatterns: gitignore.addedPatterns,
        hookInstalled: hook.installed,
        hookPath: hook.hookPath,
      };
    }

    default:
      throw new Error(`Unknown tool: ${toolCall.name}`);
  }
}
