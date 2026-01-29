# Stealth Compliance Monitor (v3.0)

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/Cognostra/Stealth-Compliance-Monitor?style=flat-square&logo=github)](https://github.com/Cognostra/Stealth-Compliance-Monitor/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![CI Status](https://img.shields.io/github/actions/workflow/status/Cognostra/Stealth-Compliance-Monitor/ci.yml?branch=main&style=flat-square&logo=github-actions&label=CI)](https://github.com/Cognostra/Stealth-Compliance-Monitor/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/Cognostra/Stealth-Compliance-Monitor?style=flat-square&logo=github)](https://github.com/Cognostra/Stealth-Compliance-Monitor/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/cognostra/stealth-compliance-monitor?style=flat-square&logo=docker)](https://hub.docker.com/r/cognostra/stealth-compliance-monitor)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20-brightgreen?style=flat-square&logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)

**The Enterprise-Grade Live-Site Security & Compliance Platform**

[📖 Documentation](https://cognostra.github.io/Stealth-Compliance-Monitor/) · [🎮 Demo Guide](docs/demo-guide.md) · [🔌 Plugins](plugins/README.md) · [🐛 Report Bug](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=bug_report.md) · [✨ Request Feature](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=feature_request.md)

</div>

---

**Stealth Compliance Monitor (LSCM)** is a comprehensive automated testing platform that performs security, performance, accessibility, and visual regression audits on **live web applications**. 

Unlike static code analysis (SAST), LSCM uses headless browsers to interact with your production application like a real user—clicking buttons, submitting forms, and bypassing bot defenses—while routing all traffic through security proxies to detect vulnerabilities that only appear at runtime.

## 🌟 What's New in v3.0

- **🚀 Fleet Mode Concurrency**: Scan hundreds of sites in parallel (`FLEET_CONCURRENCY=10`).
- **📊 Executive Reporting**: Generate one-page PDF summaries for leadership (`--executive-report`).
- **🛡️ Policy-as-Code**: Enforce custom pass/fail criteria via YAML (`.compliance-policy.yml`).
- **🤖 Continuous Monitoring**: Built-in cron scheduler for daemon-mode auditing.
- **📁 SARIF Support**: Native integration with GitHub Code Scanning.
- **🔒 Security Hardening**: 22 vulnerabilities addressed; centralized constants, stricter path validation, and enhanced error handling (see Migration Guide).
- **⚙️ New CLI Flags**: `--sarif`, `--policy`, `--compliance` for SARIF export and policy evaluation.

---

## Features

### 🔐 Security Scanning
- **Passive ZAP Analysis**: Routes traffic through OWASP ZAP to detect X-Frame-Options, missing headers, etc.
- **Active Vulnerability Scan**: Spider crawl + safe attack payloads (SQLi, XSS, IDOR) (Deep Profile only).
- **Secret Detection**: Scans JS sources for leaked API keys, AWS credentials, and PII.
- **Supabase Security**: Checks for service_role key leaks and RLS bypasses.
- **API Security Testing**: Tests REST/GraphQL endpoints for auth bypass and rate limiting.

### ⚡ Performance & Quality
- **Lighthouse Audits**: Performance, Accessibility, SEO, and Best Practices scores.
- **Core Web Vitals**: Tracks LCP, CLS, TBT, FCP with regression alerts.
- **Visual Regression**: Pixel-perfect layout monitoring with `pixelmatch`.
- **Broken Link Checker**: Validates internal and external links.

### ⚖️ Compliance & Reporting
- **Multi-Framework Mapping**: Maps findings to SOC2, GDPR, and HIPAA controls.
- **Executive PDF**: High-level summary of security health and top risks.
- **HTML Dashboard**: Interactive drill-down report with remediation guidance.
- **SARIF Export**: Standard format for CI/CD integration.

---

## 🚀 Quick Start

### Interactive Setup (Recommended)

Run the wizard to generate your configuration and `.env` file automatically:

```bash
npx ts-node src/index.ts init
```

### Manual Setup

1. **Clone & Install**:
   ```bash
   git clone https://github.com/Cognostra/Stealth-Compliance-Monitor.git
   cd Stealth-Compliance-Monitor
   npm install
   npx playwright install chromium
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your target URL and credentials
   ```

3. **Start Security Proxy (Optional but Recommended)**:
   ```bash
   docker-compose up -d zaproxy
   ```

4. **Run Your First Scan**:
   ```bash
   # Quick health check (1 page)
   npx ts-node src/index.ts --profile=smoke

   # Full compliance audit (15 pages)
   npx ts-node src/index.ts --profile=standard
   ```

---

## 🛠️ Usage & CLI Options

```bash
npx ts-node src/index.ts [options]
```

| Flag | Description |
|------|-------------|
| `--profile=<name>` | Scan profile: `smoke`, `standard`, `deep`, `deep-active` |
| `--active` | Enable active security scanning (aggressive payloads) |
| `--executive-report` | Generate a PDF executive summary |
| `--report-only` | Regenerate reports from previous scan data |
| `--headed` | Run browser normally (visible) for debugging |
| `--debug` | Enable full debug mode (pause on failure, devtools) |
| `--slow-mo=<ms>` | Slow down browser actions by N milliseconds |
| `--sarif[=path]` | Output SARIF 2.1 report (optional path; defaults to reports/results.sarif) |
| `--policy=<path>` | Evaluate a specific policy YAML file during processing |
| `--compliance` | Enable compliance mapping (SOC2/GDPR/HIPAA) during report generation |
| `init` | Launch the interactive configuration wizard |

---

## 📦 Policy-as-Code

Define strict pass/fail criteria in `.compliance-policy.yml` at the root of your project:

```yaml
policies:
  - name: "No Critical Security Issues"
    condition: "critical_count == 0"
    action: fail
  
  - name: "Performance Budget"
    condition: "lighthouse.performance >= 90"
    action: warn
    
  - name: "Max Page Load Time"
    condition: "metrics.lcp < 2500"
    action: fail
```

The scanner will evaluate these rules post-audit and exit with error code 1 if any "fail" policy is violated.

---

## 🔐 POLICY_ALLOWED_DIRS

To reduce risk from untrusted policy files, v3 introduces strict directory allow-listing for policy files. Set the POLICY_ALLOWED_DIRS environment variable to a comma-separated list of directories that policy files may be loaded from (defaults: `./policies,.`).

Example:

```bash
export POLICY_ALLOWED_DIRS=./policies,./config
```

If a policy path is outside these directories, the PolicyEngine will reject it and throw an error. See the Migration Guide below for details.

---

## 🌐 Fleet Mode & Concurrency

---

## Migration Guide (v2 -> v3)

v3 introduces several breaking changes focused on security hardening and stricter validation. Follow these steps to migrate safely:

1. Path validation: Policy file paths are now validated against POLICY_ALLOWED_DIRS (default `./policies,.`). Move any custom policy files into one of the allowed directories or update `POLICY_ALLOWED_DIRS` in your environment.

2. Constants centralization: Magic numbers and limits (e.g., YAML size limits, regex timeouts) moved to `src/v3/utils/constants.ts`. If your code depends on internal constants, update imports accordingly.

3. Error handling: File system operations may now throw more specific errors (e.g., `Permission denied reading policy file`). Ensure any integrations that read policy files handle these errors or run with appropriate permissions.

4. CLI flags: New flags `--sarif`, `--policy`, and `--compliance` were added. Scripts that relied on positional arguments should be updated to use these flags.

5. Docker: Dockerfile was optimized; baseline snapshot COPY step was removed. If your CI relied on that COPY step, add a separate step to inject baseline snapshots into `/app/snapshots/baseline/`.

6. Memory management: TrendService now exposes `cleanupOldRecords()` to prune historical data. If you persist TrendService data externally, schedule periodic cleanup to limit disk usage.

If you need help migrating, open an issue or request a migration patch with the repository owner.


## 🌐 Fleet Mode & Concurrency

Scan multiple sites efficiently with parallel execution.

1. **Define Targets** (`targets.json`):
   ```json
   ["https://app-a.com", "https://app-b.com", "https://staging.app-c.com"]
   ```

2. **Configure Concurrency** (`.env`):
   ```bash
   LIVE_URL=targets.json
   FLEET_CONCURRENCY=5  # Scan 5 sites simultaneously
   ```

3. **Run Fleet Scan**:
   ```bash
   npx ts-node src/index.ts --profile=standard
   ```

Generates a unified **Fleet Dashboard** comparing health scores across all applications.

---

## ⏰ Continuous Monitoring

Run as a background daemon to perform scheduled audits.

**Configuration (`monitoring-schedule.yml`)**:
```yaml
schedules:
  - name: "Hourly Smoke Check"
    cron: "0 * * * *"
    profile: "smoke"
    target: "https://production.com"
  
  - name: "Nightly Deep Scan"
    cron: "0 2 * * *"
    profile: "deep"
    target: "https://staging.com"
```

**Start Daemon**:
```bash
npm run monitor
```

---

## 📊 Reporting

Reports are saved to `./reports/`:

- **Interactive Dashboard**: `reports/{domain}-audit-report.html`
- **Executive Summary**: `reports/{domain}-executive-summary.pdf`
- **GitHub Security**: `reports/results.sarif`
- **Raw Data**: `reports/latest.json`

### GitHub Actions Integration

Upload SARIF results to GitHub Security tab:

```yaml
- name: Run Stealth Monitor
  run: npx ts-node src/index.ts --profile=standard

- name: Upload SARIF file
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/results.sarif
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and request features.

## 📄 License

MIT © [Cognostra](https://github.com/Cognostra)

## Disclaimer

This software is for authorized testing only. Do not run against targets without explicit permission.
