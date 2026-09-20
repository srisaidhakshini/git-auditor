/**
 * types.ts — Types for the dependency & supply chain malware scanner.
 */

import type { Severity } from '../../report/types.js';

export type DependencyFindingType =
  | 'cve'
  | 'malicious-script'
  | 'typosquat'
  | 'suspicious-telemetry'
  | 'unmaintained';

export interface DependencyFinding {
  /** Unique finding ID (e.g. CVE ID, rule ID, or synthetic hash). */
  id: string;
  /** Name of the affected package. */
  packageName: string;
  /** Current installed or declared version if known. */
  version?: string;
  /** Severity rating. */
  severity: Severity;
  /** Type / classification of supply-chain finding. */
  findingType: DependencyFindingType;
  /** Short headline summary. */
  title: string;
  /** Plain-language explanation of why this was flagged. */
  description: string;
  /** Actionable remediation instruction. */
  remediation: string;
  /** CVE ID if applicable (e.g. CVE-2023-12345). */
  cveId?: string;
  /** URL to security advisory or Socket.dev report. */
  advisoryUrl?: string;
  /** Arbitrary extra diagnostic details. */
  details?: Record<string, unknown>;
}

export interface DependencyScanResult {
  /** Full repository name. */
  repoFullName: string;
  /** Whether a package.json or dependency manifest was found. */
  manifestFound: boolean;
  /** Path to the manifest file relative to repo root. */
  manifestPath?: string;
  /** Number of direct and transitive packages scanned. */
  packageCount: number;
  /** List of detected dependency findings. */
  findings: DependencyFinding[];
  /** ISO timestamp when scan was performed. */
  scannedAt: string;
  /** Error message if scan failed. */
  error?: string;
}
