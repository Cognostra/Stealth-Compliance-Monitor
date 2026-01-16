# GitHub Repository Configuration Guide

This guide explains how to configure GitHub settings for optimal CI/CD and security.

## Branch Protection Rules

To enable branch protection for the `main` branch:

1. Go to **Settings** → **Branches** → **Add branch protection rule**
2. Set **Branch name pattern**: `main`
3. Enable the following settings:

### Required Settings

- [x] **Require a pull request before merging**
  - [x] Require approvals: 1
  - [x] Dismiss stale pull request approvals when new commits are pushed
  
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Status checks required:
    - `Lint & Type Check`
    - `Build`
    - `Unit Tests`
    - `Integration Tests`

- [x] **Require conversation resolution before merging**

### Recommended Settings

- [x] **Do not allow bypassing the above settings**
- [x] **Restrict who can push to matching branches**
  - Add your team/collaborators
- [ ] **Require signed commits** (optional, for high security)

---

## Required Repository Secrets

Navigate to **Settings** → **Secrets and variables** → **Actions**

### Required Secrets

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `LIVE_URL` | Target website URL | `https://myapp.com` |
| `TEST_EMAIL` | Test account email | `test@myapp.com` |
| `TEST_PASSWORD` | Test account password | `secure_password` |

### Optional Secrets

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `ZAP_API_KEY` | ZAP proxy API key | `openssl rand -hex 32` |
| `OPENAI_API_KEY` | OpenAI API key for AI remediation | `sk-...` |
| `CODECOV_TOKEN` | Codecov upload token | From codecov.io |
| `WEBHOOK_URL` | Slack/Teams webhook URL | `https://hooks.slack.com/...` |
| `WEBHOOK_SECRET` | HMAC secret for webhooks | Any secure string |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | `https://hooks.slack.com/...` |

---

## Codecov Setup

1. Go to [codecov.io](https://codecov.io) and sign in with GitHub
2. Add your repository
3. Copy the upload token
4. Add as `CODECOV_TOKEN` secret in GitHub

---

## Dependabot Configuration

Dependabot is already configured in `.github/dependabot.yml`. It will:

- Check npm dependencies weekly (Monday 9 AM)
- Check GitHub Actions weekly
- Check Docker images monthly
- Group minor/patch updates together
- Label PRs with `dependencies` and `automated`

To enable:

1. Go to **Settings** → **Code security and analysis**
2. Enable **Dependabot alerts**
3. Enable **Dependabot security updates**
4. Enable **Dependabot version updates**

---

## Workflow Summary

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR to main | Lint, build, test |
| `security-scan.yml` | Weekly (Sun 2AM) | Full security audit |
| `compliance-cron.yml` | Weekly (Mon 6AM) | Compliance check |

---

## Manual Security Scan

To trigger a manual security scan:

1. Go to **Actions** → **Scheduled Security Scan**
2. Click **Run workflow**
3. Select profile: `smoke`, `standard`, or `deep`
4. Optionally override target URL
5. Click **Run workflow**

Results will be uploaded as artifacts and posted to Slack (if configured).
