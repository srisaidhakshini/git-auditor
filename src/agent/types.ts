/**
 * types.ts — Types for the Agent Loop and Tool Use orchestrator.
 */

export interface AgentToolDefinition {
  name: string;
  description: string;
  input_schema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
  isDestructive?: boolean;
}

export interface AgentToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string | Array<any>;
}

export interface AgentExecutionContext {
  githubToken?: string;
  workingDir: string;
  autoConfirmNonDestructive?: boolean;
}
