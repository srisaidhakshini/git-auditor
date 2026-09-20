/**
 * types.ts — Shared report types.
 */

import type { SecretScanResult } from '../engines/secrets/types.js';
import type { DependencyScanResult } from '../engines/deps/types.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** A report for a single repository across all engines run on it. */
export interface RepoReport {
  repoFullName: string;
  htmlUrl: string;
  secrets?: SecretScanResult;
  deps?: DependencyScanResult;
}

/** The full report for a scan invocation (possibly multiple repos). */
export interface ScanReport {
  generatedAt: string;
  totalRepos: number;
  totalFindings: number;
  repos: RepoReport[];
}

