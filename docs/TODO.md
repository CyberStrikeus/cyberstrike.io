# Cyberstrike TODO List

## Discord & Community Setup

### Why Discord? (Advantages)

**1. Community Building**
- GitHub Issues = Bug reports, feature requests (formal)
- Discord = Real-time chat, support, engagement (informal)
- Users can ask questions before opening issues → Less duplicate issues

**2. User Retention**
- GitHub star → User forgets, leaves
- Discord join → Becomes community member, stays, contributes

**3. Fast Feedback Loop**
- Traditional: Release → Feedback after 1 week via issues
- With Discord: Release → Feedback within 5 minutes

**4. Trust & Transparency**
- "Is this project active?" → 500 people online on Discord = Active
- Users can talk directly with developers

**5. Marketing & Growth**
- Every Discord member is a potential evangelist
- "I recommended this to my friend" effect
- Word of mouth is the strongest marketing

**6. Statistics (Industry Examples)**
| Project | GitHub Stars | Discord Members | Correlation |
|---------|-------------|-----------------|-------------|
| Next.js | 120k | 70k+ | Very active community |
| Tailwind CSS | 80k | 50k+ | Help culture |
| Prisma | 35k | 40k+ | Community-driven |
| Cursor | 5k | 30k+ | Discord > GitHub |

**7. Why Important for Cyberstrike Specifically**
- Security tool → Trust is critical → Open community builds trust
- AI-powered → Fast-changing field → Feedback loop is essential
- Open source → Need contributors → Discord attracts them
- Pentest tool → Users will have questions → Support channel needed

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

### Discord + GitHub Actions Use Cases

**1. Release Announcement**
```
New v1.0.7 released!
→ Auto message to #announcements
→ Users immediately informed
```

**2. PR/Issue Notifications**
```
Someone found a bug
→ Posted to #github-feed
→ Community can help
```

**3. Build Status**
```
CI failed
→ Alert to #dev-alerts
→ Quick response
```

**4. Security Alerts**
```
Security vulnerability detected
→ Alert to #security
→ Urgent action
```

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
