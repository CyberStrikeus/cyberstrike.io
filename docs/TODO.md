# Cyberstrike TODO List

## Discord & Community Setup

### Discord Server Setup
**Status**: In Progress
**Priority**: High

- [ ] Create Discord server (Cyberstrike)
- [ ] Add logo/icon
- [ ] Enable Community feature

### Create Channels

**INFO Category:**
- [ ] #welcome (read-only)
- [ ] #rules (read-only)
- [ ] #announcements (read-only)
- [ ] #changelog (read-only)

**COMMUNITY Category:**
- [ ] #general
- [ ] #help
- [ ] #showcase
- [ ] #feedback

**DEVELOPMENT Category:**
- [ ] #github-feed (webhook)
- [ ] #contributors
- [ ] #dev-discussion

### Integrations
- [ ] Create GitHub webhook (for #github-feed)
- [ ] Add webhook to GitHub (releases, issues, PRs)
- [ ] Add release notification workflow (.github/workflows/notify-discord.yml)

### Content
- [ ] Write welcome message
- [ ] Write rules
- [ ] Write first announcement

### Invites & Promotion
- [ ] Create invite link
- [ ] Add Discord badge to README.md
- [ ] Add Discord link to website

---

## GitHub Actions Workflows

### Priority 1 (Soon)
- [ ] Security Scan (CodeQL) - Security scanning
- [ ] Discord Notify - Release announcements
- [ ] Dependabot - Automatic dependency updates

### Priority 2 (Later)
- [ ] Code Coverage - Test coverage reports
- [ ] Auto Label - Automatic PR labeling
- [ ] Auto Changelog - Automatic release notes

### Priority 3 (Future)
- [ ] Bundle Size Check
- [ ] Lighthouse CI
- [ ] Contributors Bot

---

## Completed

### CI/CD Setup ✅
- [x] Trunk-based development (main branch only)
- [x] Tag-based releases (v*)
- [x] 4 essential workflows (deploy, release, test, typecheck)
- [x] Remove unnecessary workflows (14 removed)
- [x] CI/CD documentation (docs/CI-CD.md)

### Playwright Installation ✅
- [x] Interactive installation prompt
- [x] Auto-detect package manager (npm/bun/pnpm)
- [x] Cleanup script for testing (testing/cleanup-playwright.sh)
