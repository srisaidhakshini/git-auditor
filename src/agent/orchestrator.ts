/**
 * orchestrator.ts — Agent Loop and Tool Orchestrator.
 *
 * Implements Claude Code-like conversational agent mode via Anthropic SDK,
 * with strict human confirmation pauses at destructive boundaries.
 */

import Anthropic from '@anthropic-ai/sdk';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { AGENT_TOOLS, executeAgentTool } from './tools.js';
import type { AgentMessage, AgentExecutionContext, AgentToolCall } from './types.js';

const REPO_STOPWORDS = new Set([
  'scan', 'check', 'find', 'clean', 'rewrite', 'purge', 'strip', 'remove', 'audit', 'list', 'show',
  'push', 'force', 'run', 'dry', 'please', 'for', 'in', 'on', 'of', 'at', 'the', 'my', 'a', 'an', 'to',
  'repo', 'repos', 'repository', 'repositories', 'history', 'secret', 'secrets', 'key', 'keys', 'leak',
  'leaks', 'dependency', 'dependencies', 'deps', 'dep', 'malware', 'packages', 'credentials', 'current',
  'setup', 'set', 'up', 'and', 'all', 'from', 'git', 'now', 'it', 'this',
]);

/** Picks a repo name ("owner/name" preferred) out of free text, ignoring command words. */
export function extractRepo(input: string): string | null {
  const tokens = input
    .split(/\s+/)
    .map((t) => t.replace(/^[^\w./-]+|[^\w./-]+$/g, ''))
    .filter(Boolean);
  const slash = tokens.find((t) => /^[\w.-]+\/[\w.-]+$/.test(t) && !/^[a-zA-Z]:/.test(t));
  if (slash) return slash;
  return tokens.find((t) => !REPO_STOPWORDS.has(t.toLowerCase()) && /^[\w.-]+$/.test(t)) ?? null;
}

export class AgentOrchestrator {
  private anthropic: Anthropic | null = null;
  private messages: AgentMessage[] = [];
  private context: AgentExecutionContext;

  constructor(context?: Partial<AgentExecutionContext>) {
    this.context = {
      workingDir: context?.workingDir || process.cwd(),
      autoConfirmNonDestructive: context?.autoConfirmNonDestructive ?? true,
      githubToken: context?.githubToken,
    };

    const apiKey = process.env['ANTHROPIC_API_KEY'];
    if (apiKey) {
      this.anthropic = new Anthropic({ apiKey });
    }
  }

  /**
   * Processes a single turn of user input.
   */
  async processUserMessage(
    userInput: string,
    onProgress?: (text: string) => void,
  ): Promise<string> {
    this.messages.push({ role: 'user', content: userInput });

    if (this.anthropic) {
      return this.runAnthropicLoop(onProgress);
    } else {
      return this.runFallbackPlanner(userInput, onProgress);
    }
  }

  /**
   * Anthropic SDK tool-calling loop.
   */
  private async runAnthropicLoop(onProgress?: (text: string) => void): Promise<string> {
    if (!this.anthropic) throw new Error('Anthropic client not initialized');

    const tools = AGENT_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema as any,
    }));

    let maxSteps = 10;
    while (maxSteps-- > 0) {
      onProgress?.(chalk.dim('🧠 Thinking...'));

      const response = await this.anthropic.messages.create({
        model: 'claude-sonnet-5',
        max_tokens: 4096,
        system:
          'You are Repo Guardian, a senior security & hygiene agent for GitHub repositories.\n' +
          'You help developers discover leaked secrets, scan malicious dependencies, safely rewrite history, and install prevention hooks.\n' +
          'Always explain your findings clearly. Never reveal unmasked secret values. Always remind users to rotate compromised credentials.',
        messages: this.messages as any,
        tools,
      });

      const toolCalls: AgentToolCall[] = [];
      let assistantText = '';

      for (const block of response.content) {
        if (block.type === 'text') {
          assistantText += block.text;
        } else if (block.type === 'tool_use') {
          toolCalls.push({
            id: block.id,
            name: block.name,
            input: block.input as Record<string, unknown>,
          });
        }
      }

      this.messages.push({ role: 'assistant', content: response.content as any });

      if (toolCalls.length === 0) {
        return assistantText;
      }

      // Execute tool calls
      const toolResults = [];
      for (const call of toolCalls) {
        const toolDef = AGENT_TOOLS.find((t) => t.name === call.name);
        onProgress?.(chalk.cyan(`🔧 Calling tool: ${call.name}(${JSON.stringify(call.input)})`));

        // Safety pause before destructive tools
        if (toolDef?.isDestructive && call.input['dry_run'] !== true) {
          const { confirmed } = await inquirer.prompt<{ confirmed: boolean }>([
            {
              type: 'confirm',
              name: 'confirmed',
              message: chalk.bold.red(
                `[Safety Gate] The agent wants to run destructive action "${call.name}". Allow?`,
              ),
              default: false,
            },
          ]);

          if (!confirmed) {
            toolResults.push({
              type: 'tool_result',
              tool_use_id: call.id,
              content: JSON.stringify({ error: 'Action aborted by human user at safety gate.' }),
            });
            continue;
          }
        }

        try {
          const output = await executeAgentTool(call, this.context);
          toolResults.push({
            type: 'tool_result',
            tool_use_id: call.id,
            content: JSON.stringify(output),
          });
        } catch (err) {
          toolResults.push({
            type: 'tool_result',
            tool_use_id: call.id,
            content: JSON.stringify({
              error: err instanceof Error ? err.message : String(err),
            }),
            is_error: true,
          });
        }
      }

      this.messages.push({ role: 'user', content: toolResults as any });
    }

    return 'Agent reached maximum tool iterations.';
  }

  /**
   * Rule-based intelligent fallback planner when no Anthropic API key is provided.
   */
  private async runFallbackPlanner(
    userInput: string,
    onProgress?: (text: string) => void,
  ): Promise<string> {
    const words = new Set(userInput.toLowerCase().match(/[a-z]+/g) ?? []);
    const has = (...w: string[]) => w.some((x) => words.has(x));
    const repoArg = extractRepo(userInput);
    const needRepo = (what: string): string =>
      `Which repository should I ${what}? Say e.g. "${what} owner/name" or just the repo name.`;

    // 1. List repos
    if (has('list', 'show') && has('repo', 'repos', 'repositories')) {
      onProgress?.(chalk.cyan('🔧 Executing tool: list_repositories()'));
      const result = await executeAgentTool({ id: '1', name: 'list_repositories', input: {} }, this.context);
      const repos = (result['repositories'] as any[]) || [];
      return (
        `Found ${repos.length} repositories:\n` +
        repos.map((r) => `  • ${r.fullName} (${r.private ? 'private' : 'public'})`).join('\n')
      );
    }

    // 2. Push (never executed from chat — needs the CLI's explicit confirmation gates)
    if (has('push') || (has('force') && has('push'))) {
      return (
        'Force-pushing rewritten history needs explicit confirmation, so I will not do it from chat.\n' +
        `Run: repo-guardian clean ${repoArg ?? '<repo>'}   (it asks for confirmation before rewriting and again before pushing)`
      );
    }

    // 3. Clean / rewrite history (preview only from the offline planner)
    if (has('clean', 'rewrite', 'purge', 'strip', 'remove') && !has('prevention')) {
      if (!repoArg) return needRepo('clean history for');
      onProgress?.(chalk.cyan(`🔧 Executing tool: rewrite_history(repo_name="${repoArg}", dry_run=true)`));
      try {
        const r = await executeAgentTool(
          { id: '1', name: 'rewrite_history', input: { repo_name: repoArg, dry_run: true } },
          this.context,
        );
        const n = r['totalCommitsToRewrite'] as number;
        return n === 0
          ? `✅ ${r['repoFullName']}: no commits contain sensitive files. Nothing to clean.`
          : `⚠️ Dry run for ${r['repoFullName']}: ${n} commit(s) contain sensitive files.\n` +
              `To actually rewrite history, run: repo-guardian clean ${r['repoFullName']}`;
      } catch (err) {
        return `Failed to analyse history: ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    // 4. Scan secrets
    if (has('scan', 'check', 'find') && has('secret', 'secrets', 'key', 'keys', 'leak', 'leaks', 'credentials')) {
      if (!repoArg) return needRepo('scan secrets in');
      onProgress?.(chalk.cyan(`🔧 Executing tool: scan_secrets(repo_name="${repoArg}")`));
      try {
        const result = await executeAgentTool(
          { id: '1', name: 'scan_secrets', input: { repo_name: repoArg } },
          this.context,
        );
        const count = result['findingsCount'] as number;
        return (
          `Secret Scan for ${result['repoFullName']}:\n` +
          (count === 0
            ? '✅ No leaked secrets detected in git history.'
            : `⚠️ Detected ${count} leaked secret(s) in git history!\nRotate them first, then run \`repo-guardian clean ${result['repoFullName']}\` to rewrite history.`)
        );
      } catch (err) {
        return `Failed to scan secrets: ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    // 5. Scan dependencies
    if (has('dep', 'deps', 'dependency', 'dependencies', 'malware', 'audit', 'packages', 'npm')) {
      if (!repoArg) return needRepo('audit dependencies in');
      onProgress?.(chalk.cyan(`🔧 Executing tool: scan_dependencies(repo_name="${repoArg}")`));
      try {
        const result = await executeAgentTool(
          { id: '1', name: 'scan_dependencies', input: { repo_name: repoArg } },
          this.context,
        );
        const count = result['findingsCount'] as number;
        return (
          `Dependency Scan for ${result['repoFullName']}:\n` +
          (count === 0
            ? `✅ Clean! Scanned ${result['packageCount']} packages without security issues.`
            : `⚠️ Found ${count} dependency issue(s).`)
        );
      } catch (err) {
        return `Failed to scan dependencies: ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    // 6. Init prevention
    if (has('prevention', 'hook', 'hooks', 'gitignore', 'protect')) {
      const pathMatch = userInput.match(/(?:in|at|for|on)\s+((?:[a-zA-Z]:)?[\w.\\/~-]*[\\/][\w.\\/~-]*|\.{1,2})(?=\s|$)/);
      const target = pathMatch?.[1];
      onProgress?.(chalk.cyan(`🔧 Executing tool: init_prevention(${target ? `target_path="${target}"` : ''})`));
      const result = await executeAgentTool(
        { id: '1', name: 'init_prevention', input: target ? { target_path: target } : {} },
        this.context,
      );
      if (result['error']) return `❌ ${result['error']}`;
      return `✓ Prevention layer initialized in ${result['targetPath']}. Updated .gitignore and installed pre-commit hook at ${result['hookPath']}.`;
    }

    // Help / general response
    return (
      `Hello! I am Repo Guardian Agent.\n\n` +
      `I can help you with:\n` +
      `  • "List my repositories"\n` +
      `  • "Scan secrets in <owner/repo>"\n` +
      `  • "Audit dependencies in <owner/repo>"\n` +
      `  • "Clean history in <owner/repo>"\n` +
      `  • "Set up prevention hooks"\n\n` +
      chalk.dim(`(Tip: Set ANTHROPIC_API_KEY environment variable for full Claude conversational reasoning)`)
    );
  }
}
