# PRD: Repo Guardian — CLI Security & Hygiene Agent

## 1. Overview

Repo Guardian is a CLI tool, structurally similar to Claude Code, that scans a
developer's GitHub repositories for leaked secrets and supply-chain malware,
and remediates both — including safely rewriting git history to remove
committed secrets. It is agent-driven: an LLM plans and orchestrates a fixed
set of well-defined tools rather than following a rigid script, so it can
handle repos with different structures, package managers, and histories.

### Problem statement
The user has repeatedly committed `.env.*` files to GitHub and has
unvetted/possibly malicious packages in `node_modules` across projects. There
is no single tool that: (a) finds these problems across all repos, (b)
explains severity, and (c) safely fixes them with human-in-the-loop
confirmation for destructive steps.

### Goals
- Detect secrets committed to git history (not just the working tree).
- Detect malicious/suspicious npm dependencies (typosquats, install-script
  payloads, known-bad packages).
- Remediate: strip secrets from history, patch `.gitignore`, flag/remove bad
  dependencies, install prevention hooks.
- Do all of this across multiple repos from one CLI invocation.
- Feel conversational/agentic (like Claude Code) — natural language in,
  planned tool calls out, human confirms destructive actions.

### Non-goals (explicitly out of scope for v1)
- Automatically rotating leaked credentials (tool will *detect and list*
  them; rotation is manual, since it requires access to third-party
  provider consoles).
- Automatically force-pushing rewritten history without explicit
  per-repo confirmation.
- Scanning private package registries other than the public npm registry.
- Language ecosystems other than Node/npm in v1 (pip, cargo, etc. are
  future work).
- A GUI. This is CLI-only.

---

## 2. Users & Use Cases

**Primary user:** the individual developer (solo or small team) managing
several personal/work GitHub repos, who wants a periodic "health check + fix"
pass across all of them.

**Core use cases:**
1. "Scan all my repos for leaked secrets and bad dependencies, tell me what's
   wrong before touching anything."
2. "Clean repo X — strip the `.env` files out of history and set up
   prevention so this doesn't happen again."
3. "Just audit my dependencies across all repos, I don't want to touch git
   history right now."
4. Recurring/scheduled use — run this monthly as a cron job or CI step,
   non-destructive scan-only mode, output a report.

---

## 3. Architecture

Three independent engines, one CLI shell, one orchestrating agent loop.

```
repo-guardian
├── cli/                  # command parsing, output formatting, confirmation prompts
├── agent/                # LLM orchestration loop (Anthropic SDK, tool-use)
├── engines/
│   ├── secrets/          # detection + history rewrite
│   ├── deps/             # dependency / malware scanning
│   └── prevention/       # git hooks, .gitignore generation
├── github/               # repo listing, clone/fetch, branch protection checks
└── report/               # structured findings → terminal + optional JSON/HTML
```

### 3.1 Agent loop
The agent loop is the "Claude Code-like" layer. It does not run engines
directly on user command alone — it converses, plans, calls tools, reports
findings, and pauses for explicit confirmation before any destructive tool
call. Tool contracts (see §4) are fixed and typed; the LLM cannot invent new
tool behavior, only sequence and parameterize existing tools.

### 3.2 Engines wrap existing best-in-class tools rather than reimplementing detection
- Secret detection: `gitleaks` (primary), `trufflehog` (optional second pass)
- History rewrite: `git filter-repo`
- Dependency/malware scanning: `npm audit` (baseline CVEs) + Socket.dev API
  or Snyk (supply-chain-specific: typosquats, suspicious install scripts,
  obfuscated payloads)
- GitHub access: Octokit / `gh` CLI

---

## 4. Functional Requirements

### 4.1 Repo discovery
- List all repos the authenticated user owns or has access to (via `gh` CLI
  auth or a provided PAT).
- Support scoping: `--repo <name>`, `--org <org>`, `--all`.
- Cache repo list locally with a manual `--refresh` flag.

### 4.2 Secret scanning (`scan_secrets` tool)
**Input:** repo path/URL, scan mode (`working-tree` | `full-history`)
**Behavior:**
- Run gitleaks against the target scope.
- Return structured findings: file path, commit SHA(s), secret type
  (best-effort classification — AWS key, generic API key, etc.), line
  location. Never print the secret value itself in full — mask it.
- Full-history scan is the default for this tool's purpose (working-tree-only
  scanning misses the actual problem — secrets already committed).

**Acceptance criteria:**
- Detects a committed `.env` file with a recognizable key pattern in a test
  fixture repo with >95% of known gitleaks rule matches.
- Never logs or persists unmasked secret values to disk or stdout.

### 4.3 History rewrite (`rewrite_history` tool) — DESTRUCTIVE, gated
**Input:** repo path, list of file paths/patterns to strip (from §4.2
findings, or user-specified), confirmed=false by default.
**Behavior:**
1. Always operate on a **fresh local clone**, never the user's live working
   copy.
2. Create a backup: either a `pre-cleanup-backup` branch pushed to a private
   location, or a local bundle file (`git bundle create`) — user chooses.
3. Dry run by default: show exactly what `git filter-repo` will remove and
   what the resulting history diff looks like, without executing.
4. Require explicit `confirmed=true` (surfaced via an interactive CLI
   confirmation, not just a flag the agent can set itself) before running the
   actual rewrite.
5. After rewrite, require a **second, separate confirmation** before any
   `git push --force`. State plainly that this rewrites public history and
   invalidates existing clones/forks/PRs.
6. If the repo has branch protection or open PRs against the affected branch,
   warn and refuse to auto-push; surface the conflict to the user.

**Acceptance criteria:**
- No path in the codebase can reach `git push --force` without two distinct
  human confirmations having occurred in that session.
- Dry-run output correctly predicts which commits/blobs will be removed,
  verified against test fixtures.
- Backup is verifiably restorable before any destructive step proceeds.

### 4.4 Dependency / malware scanning (`scan_dependencies` tool)
**Input:** repo path
**Behavior:**
- Run `npm audit --json` for known CVEs.
- Run Socket.dev (or Snyk) scan for supply-chain risk signals: packages with
  `postinstall`/`preinstall` scripts, typosquat name similarity to popular
  packages, recently-published packages with low download counts pulled in
  as transitive deps.
- Merge results into one findings list with severity (critical/high/
  medium/low) and a plain-language explanation per finding.

**Acceptance criteria:**
- Flags a known-malicious test package (from a public malicious-package
  corpus/testdata) as critical.
- Distinguishes "known CVE, patch available" from "suspicious behavior,
  investigate" in the output — these need different user responses.

### 4.5 Remediation actions for dependencies
- Suggest (never auto-run without confirmation) `npm update`/version pin
  changes for CVE fixes.
- For flagged-suspicious packages: surface the package name + reason, let
  the user decide remove vs. keep vs. pin; do not auto-delete `node_modules`
  entries without confirmation, since false positives are possible.

### 4.6 Prevention layer
- Generate/patch `.gitignore` to cover `.env*`, `node_modules`, common
  secret-bearing filenames, without clobbering existing custom entries.
- Offer to install a pre-commit hook (via `husky` + `gitleaks protect`) that
  blocks future commits containing secrets.
- One-shot setup command: `repo-guardian init-prevention [--repo <name>]`.

### 4.7 Reporting
- Default: human-readable terminal summary, grouped by repo → engine →
  severity.
- `--json` flag: machine-readable output for CI pipelines.
- `--report html`: optional static HTML summary for sharing/record-keeping.

### 4.8 CLI UX
```
repo-guardian scan [--repo|--org|--all] [--secrets-only|--deps-only] [--json]
repo-guardian clean <repo> [--dry-run] [--confirm]
repo-guardian init-prevention [--repo <name>]
repo-guardian chat            # opens the conversational agent mode
```
`chat` mode is the "Claude Code-like" experience — natural language,
multi-turn, agent plans and calls the tools above, always pausing at
destructive boundaries.

---

## 5. Safety & Guardrails (non-negotiable)

- **No silent destructive actions, ever.** Every `git filter-repo` run and
  every `force push` requires an explicit, separate, human-typed
  confirmation in that session — not a flag baked into a prior command, and
  not something the LLM can self-approve.
- **Backups before rewrite, always**, verified restorable before proceeding.
- **Secret values are never displayed unmasked**, never written to log
  files, never included in the JSON/HTML reports.
- **Rotation reminder is mandatory output**, not optional: any time a secret
  is found in history, the tool's output must state that history-cleaning
  does not undo exposure and the credential should be rotated at the
  provider.
- **Dependency removal is suggest-only** in v1 — no auto-uninstall — because
  supply-chain false positives can break a build silently.

---

## 6. Success Metrics

- Time from `repo-guardian scan --all` to actionable report: target <2 min
  for a user with ~20 repos of typical size.
- Zero destructive actions taken without the two-step confirmation flow
  (tracked via audit log of every rewrite/push event with confirmation
  timestamps).
- False-positive rate on dependency flags low enough that users don't start
  ignoring the tool (qualitative — track via a `--feedback` flag for marking
  a finding as false positive, review periodically).

---

## 7. Build Phases (maps to Antigravity workflows)

| Phase | Scope | Suggested workflow name |
|---|---|---|
| 1 | CLI skeleton, repo discovery, `scan_secrets` (read-only) | `/setup-cli` |
| 2 | `scan_dependencies`, unified reporting | `/add-dep-scan` |
| 3 | `rewrite_history` with dry-run + backup, no push | `/add-history-rewrite` |
| 4 | Confirmation-gated push flow, branch protection checks | `/gate-destructive-push` |
| 5 | Prevention layer (`.gitignore`, pre-commit hook) | `/add-prevention` |
| 6 | Agentic `chat` mode wrapping all tools via Anthropic SDK tool-use | `/wire-agent-loop` |

Each phase should ship with its own test fixtures (a throwaway repo with
known committed secrets, and a `package.json` with a known-bad test
dependency) so acceptance criteria in §4 are checkable, not just asserted.

---

## 8. Open Questions

- PAT vs. GitHub App auth for repo access — PAT is simpler for v1, GitHub
  App is better for org-wide use later.
- Socket.dev vs. Snyk for supply-chain scanning — depends on free-tier API
  limits at build time, needs a quick spike before Phase 2.
- Should `full-history` secret scanning have a size/time cap for very large
  repos (thousands of commits)? Needs a sane default timeout with an
  override flag.
