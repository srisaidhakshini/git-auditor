/**
 * audit.ts — Append-only audit logger for destructive security operations.
 *
 * Tracks every history rewrite and force push event with timestamps,
 * targets, commit SHAs, and confirmation status per PRD §5 & §6.
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { logger } from './logger.js';

export interface AuditRecord {
  timestamp: string;
  eventType:
    | 'REWRITE_DRY_RUN'
    | 'REWRITE_EXECUTED'
    | 'FORCE_PUSH_EXECUTED'
    | 'PREVENTION_INITIALIZED';
  repoFullName: string;
  details: Record<string, unknown>;
  confirmedByHuman: boolean;
}

const AUDIT_DIR = join(homedir(), '.repo-guardian');
const AUDIT_FILE = join(AUDIT_DIR, 'audit.log');

/**
 * Appends an audit record to the global audit log file.
 */
export function recordAuditEvent(
  eventType: AuditRecord['eventType'],
  repoFullName: string,
  details: Record<string, unknown>,
  confirmedByHuman: boolean = true,
): void {
  const record: AuditRecord = {
    timestamp: new Date().toISOString(),
    eventType,
    repoFullName,
    details,
    confirmedByHuman,
  };

  try {
    if (!existsSync(AUDIT_DIR)) {
      mkdirSync(AUDIT_DIR, { recursive: true });
    }
    appendFileSync(AUDIT_FILE, JSON.stringify(record) + '\n', 'utf8');
    logger.debug(`Audit event logged: ${eventType} for ${repoFullName}`);
  } catch (err) {
    logger.debug(`Failed to write audit log: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function getAuditLogPath(): string {
  return AUDIT_FILE;
}
