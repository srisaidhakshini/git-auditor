/**
 * types.ts — Shared types for the secrets engine.
 */

/** The scope of the scan — full git history (default) or just the working tree. */
export type ScanMode = 'full-history' | 'working-tree';

/** Classification of the secret type as determined by gitleaks rules. */
export type SecretType =
  | 'aws-access-key'
  | 'aws-secret-key'
  | 'github-token'
  | 'generic-api-key'
  | 'private-key'
  | 'jwt'
  | 'stripe-key'
  | 'sendgrid-key'
  | 'slack-token'
  | 'twilio-key'
  | 'google-api-key'
  | 'unknown';

/** A single secret finding from a scan. Secret value is always masked. */
export interface SecretFinding {
  /** Classification of the secret (best effort from gitleaks rule ID). */
  secretType: SecretType;
  /** The masked secret value — never the raw value. */
  maskedValue: string;
  /** The gitleaks rule ID that matched. */
  ruleId: string;
  /** File path where the secret was found (relative to repo root). */
  filePath: string;
  /** SHA of the commit where the secret first appeared. null = working tree. */
  commitSha: string | null;
  /** Commit author (for history scans). */
  author: string | null;
  /** Commit date (ISO string). */
  commitDate: string | null;
  /** Line number where the secret appears in the file. */
  lineNumber: number | null;
  /** A short fingerprint for deduplication. */
  fingerprint: string;
}

/** The result of running scan_secrets on a single repo. */
export interface SecretScanResult {
  /** The full name of the repo (owner/name). */
  repoFullName: string;
  /** The local path that was scanned. */
  scannedPath: string;
  /** The scan mode used. */
  mode: ScanMode;
  /** All findings, deduplicated by fingerprint. */
  findings: SecretFinding[];
  /** Wall-clock time taken for the scan in milliseconds. */
  durationMs: number;
  /** Whether the scan completed successfully. */
  success: boolean;
  /** Error message if success=false. */
  error?: string;
}

/**
 * Raw shape of a single entry from `gitleaks detect --report-format json`.
 * Only the fields we actually use are declared; gitleaks may emit more.
 */
export interface GitleaksRawFinding {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}
