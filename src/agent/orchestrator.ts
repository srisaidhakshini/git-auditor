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
    const inputLower = userInput.toLowerCase();

    // 1. List repos
    if (inputLower.includes('list') && (inputLower.includes('repo') || inputLower.includes('repositories'))) {
      onProgress?.(chalk.cyan('🔧 Executing tool: list_repositories()'));
      const result = await executeAgentTool({ id: '1', name: 'list_repositories', input: {} }, this.context);
      const repos = (result['repositories'] as any[]) || [];
      return (
        `Found ${repos.length} repositories:\n` +
        repos.map((r) => `  • ${r.fullName} (${r.private ? 'private' : 'public'})`).join('\n')
      );
    }

    // 2. Scan secrets in specific repo or all
    if (inputLower.includes('scan') && (inputLower.includes('secret') || inputLower.includes('key'))) {
      const match = userInput.match(/(?:in|for|repo)\s+([a-zA-Z0-9_\-./]+)/i);
      const targetRepo = match ? match[1]! : 'current';

      onProgress?.(chalk.cyan(`🔧 Executing tool: scan_secrets(repo_name="${targetRepo}")`));
      try {
        const result = await executeAgentTool(
          { id: '1', name: 'scan_secrets', input: { repo_name: targetRepo } },
          this.context,
        );
        const count = result['findingsCount'] as number;
        return (
          `Secret Scan for ${result['repoFullName']}:\n` +
          (count === 0
            ? '✅ No leaked secrets detected in git history.'
            : `⚠️ Detected ${count} leaked secret(s) in git history!\nRun \`repo-guardian clean ${result['repoFullName']}\` to rewrite history.`)
        );
      } catch (err) {
        return `Failed to scan secrets: ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    // 3. Scan dependencies
    if (inputLower.includes('dep') || inputLower.includes('malware') || inputLower.includes('audit')) {
      const match = userInput.match(/(?:in|for|repo)\s+([a-zA-Z0-9_\-./]+)/i);
      const targetRepo = match ? match[1]! : 'current';

      onProgress?.(chalk.cyan(`🔧 Executing tool: scan_dependencies(repo_name="${targetRepo}")`));
      try {
        const result = await executeAgentTool(
          { id: '1', name: 'scan_dependencies', input: { repo_name: targetRepo } },
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

    // 4. Init prevention
    if (inputLower.includes('prevention') || inputLower.includes('hook') || inputLower.includes('gitignore')) {
      onProgress?.(chalk.cyan('🔧 Executing tool: init_prevention()'));
      const result = await executeAgentTool({ id: '1', name: 'init_prevention', input: {} }, this.context);
      return `✓ Prevention layer initialized. Updated .gitignore and installed pre-commit hook at ${result['hookPath']}.`;
    }

    // 5. Help / General response
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
