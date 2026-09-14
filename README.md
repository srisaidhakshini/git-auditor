# Repo Guardian 🛡️

> Agent-driven CLI security & hygiene tool for GitHub repositories.

Repo Guardian scans your GitHub repositories for leaked secrets (across full git history) and malicious supply-chain npm packages, providing safe remediation with human-in-the-loop confirmation gates for any destructive action.

---

## 🚀 Features

- **🔍 Full-History Secret Scanning**: Detects API keys, tokens, private keys, and credentials across all branches and commits via `gitleaks`.
- **🔒 Zero-Exposure Safety**: Masking contract ensures raw secret values are never printed unmasked to stdout, stderr, logs, or reports.
- **⚡ Smart Discovery & Caching**: List owned repositories with GitHub PAT or `gh` CLI auth, with 24-hour local caching and `--refresh` invalidation.
- **📊 Formatted & Machine-Readable Output**: Clear terminal tables grouped by repository and severity, with `--json` support for CI pipelines.
- **🛡️ Human-in-the-Loop Safeguards**: Mandatory confirmation gates before destructive operations (history rewrite, force push).
- **⚠️ Mandatory Exposure Warning**: Alerts developers that history cleanup does not revoke exposed credentials and prompts rotation.

---

## 📐 Architecture

```
repo-guardian/
├── src/
│   ├── cli/                  # Command parsing, prompt confirmations, CLI entry
│   │   ├── commands/         # Sub-commands (scan, clean, init-prevention, chat)
│   │   └── prompt.ts         # Inquirer interactive confirmation gates
│   ├── github/               # GitHub authentication, repo discovery, local caching
│   ├── engines/
│   │   └── secrets/          # Gitleaks wrapper & finding normalizer
│   ├── report/               # Formatter for terminal (chalk) and JSON
│   └── utils/                # Secret masking, safe shell execution, logger
├── test/
│   ├── fixtures/             # Git repository fixtures for testing
│   └── engines/              # Integration and unit tests
└── dist/                     # Compiled JavaScript output
```

---

## 📦 Prerequisites

1. **Node.js**: `v20.0.0` or higher
2. **Git**: Installed and configured
3. **Gitleaks**:
   - macOS: `brew install gitleaks`
   - Windows: `winget install gitleaks` or `choco install gitleaks`
   - Linux: Download from [Gitleaks Releases](https://github.com/gitleaks/gitleaks/releases)

---

## 🛠️ Installation & Setup

```bash
# Clone repository
git clone https://github.com/srisaidhakshini/git-auditor.git
cd git-auditor

# Install dependencies
npm install

# Build TypeScript
npm run build

# Link globally for CLI usage
npm link
```

---

## 🔑 Authentication

Repo Guardian supports authentication via environment variable or the GitHub CLI:

### Option 1: Personal Access Token (PAT)
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

### Option 2: GitHub CLI (`gh`)
If `gh` is logged in, Repo Guardian automatically resolves your credentials:
```bash
gh auth login
```

---

## 📖 CLI Usage

```bash
# Scan a single repository for secrets
repo-guardian scan --repo my-repo --secrets-only

# Scan all owned repositories
repo-guardian scan --all --secrets-only

# Output machine-readable JSON (ideal for CI/CD)
repo-guardian scan --repo my-repo --json

# Force refresh the cached repository list
repo-guardian scan --all --refresh

# Set a per-repo scan timeout (in seconds)
repo-guardian scan --all --timeout-seconds 120
```

### Command Reference

| Command | Description | Status |
|---|---|---|
| `repo-guardian scan` | Scans repositories for secrets and vulnerabilities | **Phase 1** ✅ |
| `repo-guardian clean` | Rewrites git history safely to strip secrets | Phase 3 🚧 |
| `repo-guardian init-prevention` | Installs `.gitignore` and pre-commit hooks | Phase 5 🚧 |
| `repo-guardian chat` | Interactive AI agent mode (Anthropic SDK tool-use) | Phase 6 🚧 |

---

## 🧪 Testing & Development

```bash
# Run unit & integration test suite
npm test

# Run tests in watch mode
npm run test:watch

# Type check without emitting
npm run lint

# Run CLI during development without rebuilding
npm run dev -- scan --repo my-repo --secrets-only
```

---

## 🗺️ Roadmap & Build Phases

- [x] **Phase 1**: CLI skeleton, GitHub repo discovery, and read-only `scan_secrets` engine.
- [ ] **Phase 2**: Dependency & malware scanning (`npm audit` + Socket.dev / Snyk).
- [ ] **Phase 3**: History rewrite engine (`git filter-repo`) with backup creation and dry-run preview.
- [ ] **Phase 4**: Two-step confirmation-gated force-push flow and branch protection checks.
- [ ] **Phase 5**: Prevention layer (`.gitignore` generator + pre-commit hook setup).
- [ ] **Phase 6**: Agentic `chat` mode with LLM tool-calling orchestration.

---

## 📄 License

ISC
