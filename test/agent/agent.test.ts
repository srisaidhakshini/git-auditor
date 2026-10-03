import { describe, it, expect } from 'vitest';
import { AGENT_TOOLS, executeAgentTool } from '../../src/agent/tools.js';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('Agent Loop & Tool Orchestration', () => {
  it('defines valid tool schemas with strict parameter types', () => {
    expect(AGENT_TOOLS.length).toBeGreaterThanOrEqual(6);
    const toolNames = AGENT_TOOLS.map((t) => t.name);
    expect(toolNames).toContain('list_repositories');
    expect(toolNames).toContain('scan_secrets');
    expect(toolNames).toContain('scan_dependencies');
    expect(toolNames).toContain('rewrite_history');
    expect(toolNames).toContain('push_rewritten_history');
    expect(toolNames).toContain('init_prevention');

    const rewriteTool = AGENT_TOOLS.find((t) => t.name === 'rewrite_history');
    expect(rewriteTool?.isDestructive).toBe(true);
  });

  it('executes init_prevention tool successfully', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'agent-prevention-test-'));
    mkdirSync(join(tempDir, '.git'), { recursive: true }); // prevention requires a git repo
    try {
      const result = await executeAgentTool(
        {
          id: 'test-call-1',
          name: 'init_prevention',
          input: { target_path: tempDir },
        },
        { workingDir: tempDir },
      );

      expect(result['targetPath']).toBe(tempDir);
      expect(result['gitignoreModified']).toBe(true);
      expect(existsSync(join(tempDir, '.gitignore'))).toBe(true);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('fallback orchestrator answers assistance queries cleanly', async () => {
    const orchestrator = new AgentOrchestrator();
    const response = await orchestrator.processUserMessage('hello, what can you do?');
    expect(response).toContain('Repo Guardian Agent');
    expect(response).toContain('List my repositories');
  });
});
