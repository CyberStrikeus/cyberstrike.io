# Cyberstrike CI/CD Guide

This document explains the Cyberstrike project's CI/CD pipeline and release processes.

---

## Overview

Cyberstrike uses a **trunk-based development** strategy:

- Single main branch: `main`
- Tag-based releases: `v1.0.7`, `v1.0.8-beta.1`
- PRs are automatically checked
- Production deploy via separate branch

### Workflows

| Workflow | File | Trigger | Description |
|----------|------|---------|-------------|
| PR Check: TypeScript Validation | `typecheck.yml` | On PR | TypeScript type checking |
| PR Check: Run Tests | `test.yml` | On PR | Linux + Windows tests |
| PR Check: Code Coverage | `coverage.yml` | Push, PR | Test coverage reports |
| Security: CodeQL Analysis | `security-scan.yml` | Push, PR, Weekly | Static code security analysis |
| PR: Auto Label | `auto-label.yml` | On PR | Automatic PR labeling |
| Release: Auto Changelog | `auto-changelog.yml` | On Release | Automatic release notes |
| Release: CLI to npm + Desktop to GitHub | `release-cli.yml` | `v*` tag | npm and GitHub release |
| Deploy: SST to Cloudflare | `deploy.yml` | `production` push | Backend deployment |

### Automated Dependencies

| Tool | File | Schedule | Description |
|------|------|----------|-------------|
| Dependabot | `dependabot.yml` | Weekly (Monday) | Automatic dependency updates |

---

## 1. Daily Development

Regular development happens on the `main` branch. Pushes don't trigger any workflow.

```bash
# Write code
git add .
git commit -m "feat: add new feature"
git push origin main
```

### Commit Message Format (Conventional Commits)

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code formatting (no functional change)
- `refactor`: Code refactoring
- `test`: Adding/fixing tests
- `chore`: Build, CI, dependency updates

**Examples:**
```bash
git commit -m "feat(browser): add interactive Playwright installation"
git commit -m "fix(auth): resolve token refresh issue"
git commit -m "docs: update CI/CD documentation"
git commit -m "chore: bump version to 1.0.7"
```

---

## 2. Pull Request Process

Automated checks run when PRs are opened via feature branches.

### Steps

```bash
# 1. Create feature branch
git checkout -b feature/new-feature

# 2. Develop
# ... write code ...

# 3. Commit and push
git add .
git commit -m "feat: new feature description"
git push origin feature/new-feature

# 4. Open PR on GitHub
gh pr create --title "feat: new feature" --body "Description..."
```

### Automated Checks

These workflows run when a PR is opened:

| Workflow | Check | Duration |
|----------|-------|----------|
| PR Check: TypeScript Validation | Type errors | ~1 min |
| PR Check: Run Tests (Linux + Windows) | E2E tests | ~5 min |

A ✅ or ❌ indicator appears on the PR. Don't merge until all checks pass.

### PR Merge

```bash
# Squash merge (recommended)
gh pr merge --squash

# Or use GitHub UI "Squash and merge"
```

---

## 3. Release Process

### 3.1 Stable Release (e.g., v1.0.7)

Used for production-ready versions.

```bash
# 1. Update version (package.json)
# Update version field in packages/cyberstrike/package.json

# 2. Commit
git add .
git commit -m "chore: bump version to 1.0.7"
git push origin main

# 3. Create tag
git tag v1.0.7

# 4. Push tag (triggers workflow)
git push origin v1.0.7
```

**Result:**
- ✅ `@cyberstrike-io/cli@1.0.7` published to npm (`latest` tag)
- ✅ GitHub Release created
- ✅ Desktop binaries (Windows, macOS, Linux) attached

**User installation:**
```bash
npm install -g @cyberstrike-io/cli
# or
npm install -g @cyberstrike-io/cli@1.0.7
```

### 3.2 Beta Release (e.g., v1.0.8-beta.1)

Used for early test versions.

```bash
git tag v1.0.8-beta.1
git push origin v1.0.8-beta.1
```

**Result:**
- ✅ `@cyberstrike-io/cli@1.0.8-beta.1` published to npm (`beta` tag)
- ✅ GitHub Pre-release created

**User installation:**
```bash
npm install -g @cyberstrike-io/cli@beta
```

### 3.3 Other Pre-release Types

| Type | Tag Format | npm Tag | Usage |
|------|------------|---------|-------|
| Alpha | `v1.0.8-alpha.1` | `alpha` | Early development, unstable |
| Beta | `v1.0.8-beta.1` | `beta` | Feature-complete, testing phase |
| RC | `v1.0.8-rc.1` | `rc` | Release candidate, final testing |
| Stable | `v1.0.8` | `latest` | Production-ready |

```bash
# Alpha release
git tag v1.0.8-alpha.1 && git push origin v1.0.8-alpha.1

# Beta release
git tag v1.0.8-beta.1 && git push origin v1.0.8-beta.1

# Release candidate
git tag v1.0.8-rc.1 && git push origin v1.0.8-rc.1

# Stable release
git tag v1.0.8 && git push origin v1.0.8
```

---

## 4. Production Deployment

Used to deploy backend/API changes to production.

```bash
# Push from main to production
git push origin main:production
```

**Workflow:** `Deploy: SST to Cloudflare (Production)`

**What gets deployed:**
- SST (Serverless Stack) to Cloudflare Workers
- API endpoints
- Database migrations (if any)

---

## 5. Manual Workflow Triggering

You can manually run any workflow:

### GitHub UI
1. Go to GitHub repo → Actions tab
2. Select workflow from left menu
3. Click "Run workflow" button
4. Select branch and click "Run workflow"

### GitHub CLI
```bash
# Manually trigger release workflow
gh workflow run "Release: CLI to npm + Desktop to GitHub"

# Manually trigger test workflow
gh workflow run "PR Check: Run Tests (Linux + Windows)"
```

---

## 6. Error Handling

### Wrong Tag Created

```bash
# Delete local tag
git tag -d v1.0.7

# Delete remote tag
git push origin :v1.0.7

# or
git push origin --delete v1.0.7
```

### Workflow Failed

1. Go to GitHub Actions → Click on the failed workflow run
2. Review error logs
3. Fix the issue and retry

```bash
# Re-release with same tag (delete first, then recreate)
git push origin :v1.0.7
git tag -d v1.0.7
git tag v1.0.7
git push origin v1.0.7
```

### npm Publish Failed

- Ensure `NPM_TOKEN` secret is valid
- Verify package name is available on npm
- Use automation token for accounts with 2FA

---

## 7. Version Management

### Semantic Versioning (SemVer)

Format: `MAJOR.MINOR.PATCH`

| Change | When | Example |
|--------|------|---------|
| MAJOR | Breaking change | `1.0.0` → `2.0.0` |
| MINOR | New feature (backward compatible) | `1.0.0` → `1.1.0` |
| PATCH | Bug fix | `1.0.0` → `1.0.1` |

### Version Update

```bash
# Manual update
# Edit packages/cyberstrike/package.json

# Commit
git add packages/cyberstrike/package.json
git commit -m "chore: bump version to 1.0.8"
git push origin main

# Tag and release
git tag v1.0.8
git push origin v1.0.8
```

---

## 8. Best Practices

### Do's ✅

- Ensure tests pass before every release
- Follow semantic versioning rules
- Write meaningful commit messages
- Increment MAJOR version for breaking changes
- Test beta versions before production release

### Don'ts ❌

- Don't force push directly to `main`
- Don't release without testing
- Don't reuse the same version number
- Don't leave npm tokens in code

---

## 9. Example Scenarios

### Scenario 1: Bug Fix Release

```bash
# 1. Fix the bug
git add .
git commit -m "fix(auth): resolve login timeout issue"
git push origin main

# 2. Increment patch version
# package.json: "version": "1.0.6" → "1.0.7"
git add .
git commit -m "chore: bump version to 1.0.7"
git push origin main

# 3. Release
git tag v1.0.7
git push origin v1.0.7
```

### Scenario 2: New Feature + Beta Testing

```bash
# 1. Develop feature
git add .
git commit -m "feat(browser): add screenshot capture"
git push origin main

# 2. Beta release
git tag v1.1.0-beta.1
git push origin v1.1.0-beta.1

# 3. Get feedback, fix issues
git add .
git commit -m "fix(browser): improve screenshot quality"
git push origin main

# 4. Second beta
git tag v1.1.0-beta.2
git push origin v1.1.0-beta.2

# 5. Stable release
# package.json: "version": "1.1.0"
git add .
git commit -m "chore: bump version to 1.1.0"
git push origin main
git tag v1.1.0
git push origin v1.1.0
```

### Scenario 3: Hotfix

```bash
# Quick fix for critical bug
git add .
git commit -m "fix(critical): patch security vulnerability"
git push origin main

# Immediate release
# package.json: "version": "1.0.8"
git add .
git commit -m "chore: bump version to 1.0.8"
git push origin main
git tag v1.0.8
git push origin v1.0.8
```

---

## 10. Useful Commands

```bash
# List all tags
git tag -l

# Last 5 tags
git tag -l | tail -5

# Tag details
git show v1.0.7

# Workflow status
gh run list --limit 5

# Workflow logs
gh run view <run-id> --log

# npm versions
npm view @cyberstrike-io/cli versions

# npm latest version
npm view @cyberstrike-io/cli version

# npm beta version
npm view @cyberstrike-io/cli dist-tags.beta
```

---

## 11. Security Scanning (CodeQL)

### Why Security Scanning?

For a security testing tool like Cyberstrike, code security is paramount. CodeQL provides:

- **Static Analysis**: Detects vulnerabilities before runtime
- **OWASP Coverage**: Identifies SQL injection, XSS, command injection, etc.
- **Automated Auditing**: Every PR and push is automatically scanned
- **GitHub Integration**: Results appear in Security tab and PR comments

### How It Works

CodeQL analyzes the codebase using semantic queries:

1. **Build Phase**: Creates a database of the code structure
2. **Analysis Phase**: Runs security queries against the database
3. **Report Phase**: Generates findings with severity levels

### When It Runs

| Trigger | Description |
|---------|-------------|
| Push to main/dev | Every commit is scanned |
| Pull Request | PRs are blocked if critical issues found |
| Weekly (Monday 00:00 UTC) | Scheduled scan for new vulnerability patterns |
| Manual | Can be triggered from Actions tab |

### Viewing Results

1. Go to GitHub repo → Security tab → Code scanning alerts
2. Or view in PR → Checks → CodeQL

### Severity Levels

| Level | Action |
|-------|--------|
| Critical | Block merge, fix immediately |
| High | Block merge, fix before release |
| Medium | Warning, fix in next sprint |
| Low | Informational, fix when convenient |

### Customization

The workflow uses extended security queries:
- `security-extended`: Additional security rules
- `security-and-quality`: Code quality + security combined

---

## 12. Dependency Management (Dependabot)

### Why Dependabot?

Outdated dependencies are a major security risk. Dependabot provides:

- **Automatic Updates**: Creates PRs for outdated packages
- **Security Alerts**: Notifies when dependencies have known vulnerabilities
- **Version Grouping**: Groups minor/patch updates to reduce PR noise
- **GitHub Actions**: Also keeps workflow actions up to date

### Configuration

Located at `.github/dependabot.yml`:

```yaml
version: 2
updates:
  # npm dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    groups:
      minor-and-patch:
        patterns: ["*"]
        update-types: ["minor", "patch"]

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### How It Works

1. **Weekly Scan**: Every Monday, Dependabot checks for updates
2. **PR Creation**: Creates PRs for outdated dependencies
3. **Grouping**: Minor and patch updates are grouped together
4. **CI Check**: Your existing test/typecheck workflows run on these PRs
5. **Review & Merge**: Review the PR, then merge if tests pass

### Handling Dependabot PRs

```bash
# View open Dependabot PRs
gh pr list --author "dependabot[bot]"

# Merge a Dependabot PR
gh pr merge <PR_NUMBER> --squash
```

### Security Alerts

When a dependency has a known vulnerability:
1. GitHub creates a security alert
2. Dependabot creates a security update PR
3. These PRs are marked with "security" label
4. **Priority**: Merge security PRs immediately

### Ignoring Updates

Major version updates are ignored by default to prevent breaking changes:

```yaml
ignore:
  - dependency-name: "*"
    update-types: ["version-update:semver-major"]
```

To update a major version manually:
```bash
# Update a specific package
bun update <package-name>

# Or edit package.json and run
bun install
```

---

## 13. Automatic PR Labeling

### Why Auto Label?

Manual labeling is tedious and inconsistent. Auto Label provides:

- **Consistency**: Every PR gets labeled the same way
- **Filtering**: Easily filter PRs by type, scope, or package
- **Changelog**: Labels drive automatic release notes generation
- **Visibility**: Instantly see what a PR affects without reading the diff

### How It Works

The workflow runs on every PR and applies labels based on two criteria:

**1. PR Title (Conventional Commits)**

| Title Prefix | Label |
|--------------|-------|
| `feat:` | `feature` |
| `fix:` | `bug` |
| `docs:` | `documentation` |
| `refactor:` | `refactor` |
| `perf:` | `performance` |
| `test:` | `testing` |
| `chore:` | `chore` |
| `ci:` | `ci` |

**2. Scope in Title**

| Scope | Label |
|-------|-------|
| `(cli)` | `cli` |
| `(tui)` | `tui` |
| `(sdk)` | `sdk` |
| `(web)` | `web` |
| `(mcp)` | `mcp` |
| `(security)` | `security` |
| `(deps)` | `dependencies` |

**3. Files Changed**

| Path | Label |
|------|-------|
| `packages/cyberstrike/` | `cli` |
| `packages/web/` | `web` |
| `packages/sdk/` | `sdk` |
| `packages/desktop/` | `desktop` |
| `docs/` or `*.md` | `documentation` |
| `.github/` | `ci` |
| `*test*` or `*spec*` | `testing` |

**4. Special Cases**

| Condition | Label |
|-----------|-------|
| Dependabot PR | `dependencies` + `automated` |
| Title contains `breaking` or `!:` | `breaking-change` |
| Title contains `urgent` | `priority-high` |

### Example

A PR titled `feat(cli): add new scan command` that modifies files in `packages/cyberstrike/` will get:
- `feature` (from `feat:` prefix)
- `cli` (from `(cli)` scope and file path)

### Viewing Labels

```bash
# List all labels
gh label list

# Filter PRs by label
gh pr list --label feature
gh pr list --label bug
```

---

## 14. Automatic Changelog (Release Notes)

### Why Auto Changelog?

Writing release notes manually is time-consuming and error-prone. Auto Changelog provides:

- **Automatic Generation**: Creates release notes from commit history
- **Categorization**: Groups changes by type (features, fixes, security, etc.)
- **Consistency**: Every release follows the same format
- **Traceability**: Each entry links to its commit

### How It Works

When a GitHub Release is created:

1. **Tag Detection**: Identifies the current and previous tags
2. **Commit Analysis**: Reads all commits between the two tags
3. **Categorization**: Sorts commits by conventional commit prefix
4. **Formatting**: Generates markdown with categories, icons, and commit links
5. **Update**: Updates the GitHub Release body with the generated notes

### Categories

| Prefix | Category | Icon |
|--------|----------|------|
| `feat:` | Features | 🚀 |
| `fix:` | Bug Fixes | 🐛 |
| `security` keyword | Security | 🔒 |
| `perf:` | Performance | ⚡ |
| `docs:` | Documentation | 📝 |
| `ci:`, `chore(ci):` | CI/CD | ⚙️ |
| Other | Other | 📦 |

### Example Output

```markdown
### 🚀 Features

- Add interactive Playwright installation prompt ([`abc1234`])
- Add CodeQL security scanning workflow ([`def5678`])

### 🐛 Bug Fixes

- Update @clack/prompts API compatibility ([`ghi9012`])

### 🔒 Security

- Update astro packages to patch vulnerabilities ([`jkl3456`])

---

### Installation
npm install -g @cyberstrike-io/cli
```

### When It Runs

| Trigger | Description |
|---------|-------------|
| Release created | Automatically updates the release notes |
| Manual | Run with a specific tag via Actions tab |

### Manual Trigger

```bash
# Generate changelog for a specific tag
gh workflow run "Release: Auto Changelog" --field tag=v1.0.7
```

### Prerequisites

For the best results, follow [Conventional Commits](https://www.conventionalcommits.org/) in your commit messages:

```bash
feat(cli): add new scan command          # → Features
fix(auth): resolve token refresh issue   # → Bug Fixes
fix(security): patch XSS vulnerability   # → Security
perf(tui): optimize rendering            # → Performance
docs: update getting started guide       # → Documentation
chore(ci): update CodeQL action          # → CI/CD
```

---

## 15. Code Coverage

### Why Code Coverage?

Code coverage measures how much of the codebase is exercised by tests. For a security tool like Cyberstrike, high coverage means:

- **Confidence**: More code tested = fewer hidden bugs
- **Visibility**: See exactly which files and functions lack tests
- **Regression Prevention**: Coverage drops alert you when PRs remove test coverage
- **Quality Gate**: Block PRs that significantly reduce coverage

### How It Works

1. **Test Run**: `bun test --coverage` runs all unit tests with coverage tracking
2. **Report Generation**: Produces an LCOV report with per-file coverage data
3. **Upload**: Sends the report to Codecov for analysis and tracking
4. **PR Comment**: Codecov posts a comment on the PR showing coverage changes

### When It Runs

| Trigger | Description |
|---------|-------------|
| Push to main | Track baseline coverage |
| Pull Request | Compare PR coverage vs main |
| Manual | Run from Actions tab |

### Codecov Setup

Codecov is free for public open source repos. To complete the setup:

1. Go to [codecov.io](https://codecov.io) and sign in with GitHub
2. Add the `CyberStrikeus/cyberstrike.io` repository
3. (Optional) Add `CODECOV_TOKEN` to repo secrets for private uploads

### Reading Coverage Reports

Codecov provides:

| Metric | Description |
|--------|-------------|
| **Line Coverage** | Percentage of code lines executed by tests |
| **Branch Coverage** | Percentage of conditional branches tested |
| **Patch Coverage** | Coverage of only the changed lines in a PR |
| **Project Coverage** | Overall repository coverage trend |

### PR Comment Example

```
Coverage Report
  Merging #15 into main will increase coverage by +2.3%

@@            Coverage Diff            @@
##             main     #15     +/-    ##
=========================================
+ Coverage    72.5%   74.8%   +2.3%
  Files          85      87      +2
  Lines        4200    4350    +150
=========================================
+ Hits         3045    3257    +212
  Misses       1155    1093     -62
```

### Adding Coverage Badge to README

After the first report, add to `README.md`:

```markdown
[![codecov](https://codecov.io/gh/CyberStrikeus/cyberstrike.io/branch/main/graph/badge.svg)](https://codecov.io/gh/CyberStrikeus/cyberstrike.io)
```

---

## Resources

- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [npm Publishing](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Dependabot Configuration](https://docs.github.com/en/code-security/dependabot)
- [Codecov Documentation](https://docs.codecov.io/)
