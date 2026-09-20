# Repo Guardian 🛡️

> Agent-driven CLI security & hygiene tool for GitHub repositories.

Repo Guardian finds leaked secrets (across full git history) and suspicious npm dependencies in your GitHub repositories, helps you remove them safely, and installs guardrails so they don't come back. Every destructive action (history rewrite, force push) is gated behind explicit human confirmation, backed up first, and written to an audit log.

---

## Table of contents

1. [Features](#-features)
2. [How it works](#-how-it-works)
3. [Prerequisites](#-prerequisites)
4. [Installation](#-installation)
5. [Authentication](#-authentication)
6. [Command reference](#-command-reference)
   - [`auth`](#repo-guardian-auth) · [`scan`](#repo-guardian-scan) · [`clean`](#repo-guardian-clean-repo) · [`init-prevention`](#repo-guardian-init-prevention) · [`chat`](#repo-guardian-chat)
7. [Recommended workflow](#-recommended-workflow)
8. [Safety model](#-safety-model)
9. [Files Repo Guardian writes](#-files-repo-guardian-writes)
10. [Architecture](#-architecture)
11. [Testing & development](#-testing--development)
12. [Troubleshooting](#-troubleshooting)

---

## 🚀 Features

| Phase | Capability |
|---|---|
| 1 | **Secret scanning** – full git history of any repo you own, via `gitleaks` (or a built-in fallback scanner). Discovery of your repos with 24h caching. |
| 2 | **Dependency scanning** – `npm audit` CVEs, malicious lifecycle scripts, and typosquatted package names. Unified terminal / JSON / HTML reports. |
| 3 | **History rewrite** – dry-run preview, verified backup bundle, then removal of sensitive files from every commit. |
| 4 | **Gated push** – branch-protection and open-PR checks, then a second explicit confirmation before `git push --force`. |
| 5 | **Prevention** – `.gitignore` hardening and a git `pre-commit` hook that blocks secrets. |
| 6 | **Agentic `chat`** – talk to the tools in natural language. Uses Claude tool-use when `ANTHROPIC_API_KEY` is set, otherwise a built-in offline planner. |

Cross-cutting: secrets are **always masked** in output, and a mandatory *"rotate your credentials"* warning follows every finding.

---

## 🧠 How it works

### 1. Authentication & repo discovery
Repo Guardian resolves a GitHub token in this order: `GITHUB_TOKEN` env var → token saved by `auth login` → `gh auth token`. With the token it calls the GitHub API (Octokit) to look up one repo (`--repo`) or list everything you own (`--all`). The `--all` list is cached for 24 hours in `~/.repo-guardian/repo-cache.json`; `--refresh` bypasses the cache.

### 2. Cloning
Each target repo is **fully cloned** (all history, no `--depth`) into a temporary directory, scanned, and the directory is deleted afterwards. Your local working copies are never touched by `scan`.

### 3. Secrets engine
- **With gitleaks installed:** `gitleaks detect` is run over the entire history of all branches, and its JSON report is normalised into findings (type, rule, file, line, commit, author, date).
- **Without gitleaks:** a native fallback scans `git log -p --all` plus the working tree using built-in rules (AWS access/secret keys, GitHub PATs, private keys, Stripe & SendGrid keys, generic env secrets) and flags committed `.env` files. It works out of the box but is less thorough than gitleaks.
- Every raw value is passed through the **masking contract** (`AKIA****`) before it reaches any output, log, or report. Findings are de-duplicated by fingerprint.

### 4. Dependency engine
Reads `package.json` in the cloned repo and runs three checks:
1. **`npm audit`** for known CVEs.
2. **Malicious script heuristics** – lifecycle hooks (`preinstall`, `postinstall`, …) that do things like `curl … | bash`, base64-decode-and-eval, or exfiltrate data.
3. **Typosquat detection** – edit-distance comparison against a list of popular npm packages (e.g. `expresss` ≈ `express`).

Findings carry a severity (`critical` / `high` / `medium` / `low`) and a remediation hint.

### 5. Reporting
Results from both engines are merged into one report per repo: coloured terminal output grouped by severity, `--json` for machines, or `--report html` for a shareable page. `scan` exits with code **1 if anything was found** and **0 if clean**, so it drops straight into CI.

### 6. Safe remediation (`clean`)
```
clone → dry-run (which commits/files?) → confirm #1 → verified backup bundle
      → rewrite history (git filter-repo, or filter-branch fallback)
      → rotation reminder → confirm #2 → branch-protection + PR checks → force push
```
- **Dry-run** lists every affected commit and matched file without changing anything.
- **Backup:** `git bundle create --all`, then `git bundle verify`. If the bundle can't be verified, nothing is rewritten.
- **Rewrite** removes the matching paths from all commits and reports HEAD before/after.
- **Push** is separate and separately confirmed. It refuses if the branch is protected against force-pushes, warns about open PRs that will conflict, and only then runs `git push --force origin <branch>`.
- Every rewrite/push is appended to the audit log.

### 7. Prevention (`init-prevention`)
Appends a marked block of secret-related patterns to `.gitignore` (idempotent — running it twice doesn't duplicate) and installs `.git/hooks/pre-commit`. The hook runs `gitleaks protect --staged` when gitleaks is available and always blocks staged sensitive filenames (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`; `.env.example` is allowed).

### 8. Agent mode (`chat`)
An orchestrator exposes the engines as tools (`list_repositories`, `scan_secrets`, `scan_dependencies`, `rewrite_history`, `push_rewritten_history`, `init_prevention`). With `ANTHROPIC_API_KEY` set, Claude plans and calls them in a tool-use loop (max 10 steps per message). Without a key, a keyword-based planner handles simple requests. Destructive tools **always** pause for a `[Safety Gate]` confirmation unless they run with `dry_run: true`.

---

## 📦 Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| Node.js ≥ 20 | everything | |
| Git | everything | |
| GitHub auth | scan / clean | see [Authentication](#-authentication) |
| `gitleaks` | *optional* | Better secret detection. `winget install gitleaks`, `brew install gitleaks`, or [releases](https://github.com/gitleaks/gitleaks/releases). Falls back to the built-in scanner if absent. |
| `git-filter-repo` | *optional* | Faster/safer rewrites. Falls back to `git filter-branch`. |
| `npm` | dependency scan | for `npm audit` |
| `ANTHROPIC_API_KEY` | *optional* | Enables full Claude reasoning in `chat`. |

---

## 🛠️ Installation

```bash
git clone https://github.com/srisaidhakshini/git-auditor.git
cd git-auditor
npm install
npm run build
npm link        # makes `repo-guardian` available globally
```

Without linking you can use `node dist/cli/index.js <command>` or `npm run dev -- <command>`.

---

## 🔑 Authentication

**Browser login (recommended)**
```bash
repo-guardian auth login
```
Shows a one-time code and opens `https://github.com/login/device`. The token is stored in `~/.repo-guardian/config.json`.

**Personal Access Token**
```bash
repo-guardian auth login --pat            # paste a token when prompted
export GITHUB_TOKEN=ghp_xxx               # bash/zsh
$env:GITHUB_TOKEN = "ghp_xxx"             # PowerShell
```
Needed scopes: `repo`, `read:user`.

**GitHub CLI** – if `gh auth login` is done, it's picked up automatically.

---

## 📖 Command reference

Global: `repo-guardian --help`, `repo-guardian --version`, `repo-guardian <command> --help`.

### `repo-guardian auth`

| Subcommand | Description |
|---|---|
| `auth login` | Log in via browser device flow. |
| `auth login --pat` | Log in by pasting a Personal Access Token. |
| `auth login --client-id <id>` | Use your own GitHub OAuth App for device flow. |
| `auth status` | Show who you're logged in as and which source is used. |
| `auth logout` | Delete the stored token. |

### `repo-guardian scan`

Read-only. Scans repositories for secrets and dependency problems. You must pass `--repo` or `--all`.

| Option | Description |
|---|---|
| `--repo <name>` | One repository (`owner/name` or bare `name`). |
| `--all` | Every repository you own. |
| `--secrets-only` | Run only the secrets engine. |
| `--deps-only` | Run only the dependency engine. (Can't combine with `--secrets-only`.) |
| `--json` | Shorthand for `--report json`. |
| `--report <format>` | `terminal` (default), `json`, or `html`. |
| `--output <file>` | Write the report to a file instead of stdout. |
| `--refresh` | Ignore the 24h repo-list cache. |
| `--timeout-seconds <n>` | Per-repo scan timeout; `0` = unlimited. |

```bash
repo-guardian scan --repo my-repo                       # secrets + deps
repo-guardian scan --all --secrets-only                 # every repo, secrets only
repo-guardian scan --repo my-repo --deps-only           # dependencies only
repo-guardian scan --all --report html --output report.html
repo-guardian scan --repo my-repo --json > findings.json
repo-guardian scan --all --refresh --timeout-seconds 120
```
**Exit code:** `0` clean, `1` findings (or error).

### `repo-guardian clean <repo>`

Removes sensitive files from a repo's **entire git history**. Works on a fresh temporary clone.

| Option | Description |
|---|---|
| `--dry-run` | Only list affected commits/files. Changes nothing. |
| `--confirm` | Skip the interactive "rewrite history?" prompt. |
| `--patterns <list>` | Comma-separated file patterns. Default: `.env, .env.*, *.pem, *.key, id_rsa`. |
| `--branch <name>` | Branch to push (default: the repo's default branch). |
| `--backup-dir <dir>` | Where to write the backup `.bundle` (default: `<tmp>/repo-guardian-backups`). |
| `--force-push` | Pre-confirm the force-push step. |

```bash
repo-guardian clean my-repo --dry-run                    # always start here
repo-guardian clean my-repo                              # interactive, prompts twice
repo-guardian clean my-repo --patterns ".env,secrets.json,*.pfx"
repo-guardian clean my-repo --backup-dir ./backups
```
Restore from a backup with `git clone <file>.bundle restored-repo`.

> ⚠️ Force-pushing rewrites public history: collaborators must re-clone or reset. And **rewriting history does not un-leak a secret** — rotate every exposed credential.

### `repo-guardian init-prevention`

| Option | Description |
|---|---|
| `--path <path>` | Directory of the repo to protect (default: current directory). |
| `--repo <name>` | Repo name used only for the audit log. |

```bash
cd my-project && repo-guardian init-prevention
repo-guardian init-prevention --path ../another-repo
```

### `repo-guardian chat`

Conversational agent. Type `exit`, `quit`, `:q`, or press Ctrl-C to leave.

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # optional but recommended
repo-guardian chat
```
```
guardian> list my repos
guardian> scan my-repo for secrets
guardian> check dependencies in my-repo
guardian> do a dry run of cleaning .env from my-repo
guardian> set up prevention in this directory
```
Available agent tools: `list_repositories`, `scan_secrets`, `scan_dependencies`, `rewrite_history` (supports `dry_run`), `push_rewritten_history`, `init_prevention`. Destructive ones prompt for confirmation every time.

---

## 🧭 Recommended workflow

1. `repo-guardian auth login`
2. `repo-guardian scan --all` – find what's wrong.
3. **Rotate every leaked credential** at its provider.
4. `repo-guardian clean <repo> --dry-run` – review what would be removed.
5. `repo-guardian clean <repo>` – confirm, back up, rewrite, then confirm the force push.
6. `repo-guardian init-prevention` inside each local clone – stop it recurring.
7. Add `repo-guardian scan --all --json` to CI; a non-zero exit fails the build.

---

## 🔒 Safety model

- **Masking:** raw secret values never appear in stdout, logs, JSON, or HTML.
- **Two confirmation gates:** one before rewriting, another before force-pushing (skippable only via explicit `--confirm` / `--force-push`).
- **Verified backup** before any rewrite; failure to verify aborts.
- **Temp clones only:** your working directories are never modified by `scan` or `clean`.
- **Branch-protection check** blocks pushes to branches that forbid force-pushes; open PRs trigger a warning.
- **Agent safety gate:** destructive agent tools always require a human "yes".
- **Audit log** of dry-runs, rewrites, force-pushes and prevention setup.
- **Rotation reminder** is printed whenever secrets are found or history is cleaned.

---

## 🗂️ Files Repo Guardian writes

| Path | Purpose |
|---|---|
| `~/.repo-guardian/config.json` | Stored GitHub token from `auth login`. |
| `~/.repo-guardian/repo-cache.json` | 24h cache of your repository list. |
| `~/.repo-guardian/audit.log` | Append-only log of rewrite / push / prevention events (JSON lines: timestamp, event, repo, details, `confirmedByHuman`). |
| `<tmp>/repo-guardian-backups/*.bundle` | Pre-rewrite backups. |
| `.gitignore`, `.git/hooks/pre-commit` | Written by `init-prevention` in the target repo. |

---

## 📐 Architecture

```
src/
├── cli/
│   ├── index.ts, prompt.ts
│   └── commands/           auth, scan, clean, init-prevention, chat
├── github/                 auth (token resolution), device-flow, config, repos, cache, protection
├── engines/
│   ├── secrets/            scanner (gitleaks + fallback), rewriter, pusher
│   ├── deps/               npm audit, script heuristics, typosquat detection
│   └── prevention/         gitignore, hooks
├── agent/                  orchestrator (Claude loop + offline planner), tool definitions
├── report/                 terminal / JSON / HTML formatters
└── utils/                  mask, shell, logger, audit
test/                       unit + integration tests, fixtures (dirty-repo, malicious-repo)
```

---

## 🧪 Testing & development

```bash
npm test               # run the whole suite
npm run test:watch
npm run lint           # tsc --noEmit
npm run build
npm run dev -- scan --repo my-repo --secrets-only
```
Fixtures: `test/fixtures/dirty-repo` (git repo with committed secrets) and `test/fixtures/malicious-repo` (`package.json` with a typosquat and a `curl | bash` postinstall).

---

## 🩺 Troubleshooting

| Symptom | Fix |
|---|---|
| `No GitHub authentication found` | Run `repo-guardian auth login`, set `GITHUB_TOKEN`, or `gh auth login`. |
| Few/no secrets found on a repo you know has some | Install `gitleaks` for broader rule coverage. |
| `Repository not found or access denied (404)` | Check the name and that your token has `repo` scope. |
| Force push blocked | Branch protection forbids force pushes — temporarily allow them in GitHub settings or use another branch. |
| `chat` says to set an API key | Set `ANTHROPIC_API_KEY`, or keep using the offline planner. |
| Stale repo list | Add `--refresh`. |

---

## 📄 License

ISC
