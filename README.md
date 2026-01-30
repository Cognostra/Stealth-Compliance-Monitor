# Stealth Compliance Monitor (v3.2)

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

## What's New in v3.2

### 🔬 Advanced Security Scanners
- **SBOM Generator**: Detects npm packages and dependencies from runtime JavaScript. Queries OSV database for known vulnerabilities. `SBOM_SCANNER_ENABLED=true`
- **GraphQL Deep Scanner**: Introspection detection, query depth testing, batch query analysis, and field suggestion enumeration. `GRAPHQL_SCANNER_ENABLED=true`
- **WebSocket Auditor**: Monitors ws:// connections for plaintext auth, sensitive data leakage, and rate limiting issues. `WEBSOCKET_AUDITOR_ENABLED=true`
- **CSP Violation Collector**: Real-time Content Security Policy violation detection via `securitypolicyviolation` events. `CSP_COLLECTOR_ENABLED=true`

### 🤖 AI-Powered Analysis
- **Visual AI Compliance**: Automated color contrast checking (WCAG AA), alt text validation, and brand color compliance against palette guides. `VISUAL_AI_COMPLIANCE_ENABLED=true`
- **Behavioral Fingerprinting Detection**: Detects canvas, WebGL, AudioContext, and battery API fingerprinting techniques. `FINGERPRINT_DETECTION_ENABLED=true`
- **AI-Generated Test Flows**: Uses LLM (Ollama/OpenAI) to generate test flows from page DOM structure. `AI_TEST_FLOW_GENERATOR_ENABLED=true`
- **Smart False Positive Filter**: Confidence scoring, duplicate merging, and correlation analysis to reduce noise. `FALSE_POSITIVE_FILTER_ENABLED=true`
- **Privacy Policy Analyzer**: GDPR Article 13/14 and CCPA compliance checking against actual cookie/tracker usage. `PRIVACY_POLICY_ANALYZER_ENABLED=true`

### 🌐 Web Platform Security
- **WebRTC Analyzer**: Detects IP leaks, insecure TURN servers, and data channel vulnerabilities. `WEBRTC_ANALYZER_ENABLED=true`
- **PWA Security Scanner**: Service worker analysis, manifest.json security, and offline storage inspection. `PWA_SCANNER_ENABLED=true`
- **Browser Extension Audit**: Detects extension injections and messaging vulnerabilities. `EXTENSION_AUDIT_ENABLED=true`
- **Mobile Security Scanner**: Device orientation, touch gesture, and viewport security analysis. `MOBILE_SECURITY_SCANNER_ENABLED=true`
- **Shadow DOM Scanner**: Web Components accessibility and security assessment. `SHADOW_DOM_SCANNER_ENABLED=true`

### 🏗️ Infrastructure & DevSecOps
- **WebAssembly Security**: WASM module analysis for memory safety and unsafe operations. `WASM_SCANNER_ENABLED=true`
- **Container Scanner**: Dockerfile and docker-compose security auditing. `CONTAINER_SCANNER_ENABLED=true`
- **Kubernetes Security**: Manifest analysis for security misconfigurations. `K8S_SCANNER_ENABLED=true`
- **API Contract Testing**: OpenAPI/Swagger specification validation. `API_CONTRACT_TESTING_ENABLED=true`
- **Chaos Engineering**: Fault injection testing for resilience validation. `CHAOS_TESTING_ENABLED=true`
- **Multi-Region Compliance**: Geographic compliance testing across regions. `MULTI_REGION_COMPLIANCE_ENABLED=true`

### 🏢 Enterprise Features
- **FAIR Risk Quantification**: Factor Analysis of Information Risk calculations. `FAIR_RISK_QUANTIFICATION_ENABLED=true`
- **Compliance Drift Detection**: Detects configuration drift over time. `DRIFT_DETECTION_ENABLED=true`
- **Third-Party Risk Aggregation**: SecurityScorecard/BitSight integration. `THIRD_PARTY_RISK_ENABLED=true`
- **Real-Time Dashboard**: Live security monitoring with WebSocket updates. `REALTIME_DASHBOARD_ENABLED=true`
- **Evidence Vault**: Tamper-proof evidence storage for legal hold. `EVIDENCE_VAULT_ENABLED=true`

### 🔌 Developer Integrations
- **VS Code Extension**: IDE integration for instant compliance feedback. `VSCODE_INTEGRATION_ENABLED=true`
- **GitHub App**: PR comments, checks API, and repository scanning. `GITHUB_INTEGRATION_ENABLED=true`
- **Postman/Newman**: Collection import and CI/CD integration. `POSTMAN_INTEGRATION_ENABLED=true`
- **JIRA/ServiceNow**: Automated ticket creation for findings. `TICKETING_INTEGRATION_ENABLED=true`
- **Slack/Teams**: Real-time security alerts and notifications. `MESSAGING_INTEGRATION_ENABLED=true`

## What's New in v3.1

- **Electron App Auditing**: Scan Electron desktop apps with `--target-type=electron --electron-path=/path/to/app`. Checks for nodeIntegration, contextIsolation, remote module, CSP, and IPC exposure.
- **Flutter Web Semantics**: Accessibility auditing for Flutter web builds with `--flutter-semantics`. Inspects `flt-semantics` DOM elements for ARIA completeness, focus management, and live regions.
- **Local LLM Remediation**: Generate remediation code via local Ollama instance with `--ai-fix[=model]`. Post-scan processing reads findings and produces fix suggestions.
- **Fintech Compliance Profile**: New `--profile=fintech` for financial/crypto compliance. Detects crypto-jacking, PCI-DSS violations, and wallet drainer scripts.
- **Python Plugin Bridge**: Run custom compliance checks written in Python via `custom_checks/python/`. Scripts receive JSON context and return structured violations.

## What's New in v3.0

- **Fleet Mode Concurrency**: Scan hundreds of sites in parallel (`FLEET_CONCURRENCY=10`).
- **Executive Reporting**: Generate one-page PDF summaries for leadership (`--executive-report`).
- **Policy-as-Code**: Enforce custom pass/fail criteria via YAML (`.compliance-policy.yml`).
- **Continuous Monitoring**: Built-in cron scheduler for daemon-mode auditing.
- **SARIF Support**: Native integration with GitHub Code Scanning.
- **Security Hardening**: 22 vulnerabilities addressed; centralized constants, stricter path validation, and enhanced error handling (see Migration Guide).
- **New CLI Flags**: `--sarif`, `--policy`, `--compliance` for SARIF export and policy evaluation.

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
| `--profile=<name>` | Scan profile: `smoke`, `standard`, `deep`, `deep-active`, `fintech` |
| `--active` | Enable active security scanning (aggressive payloads) |
| `--executive-report` | Generate a PDF executive summary |
| `--report-only` | Regenerate reports from previous scan data |
| `--headed` | Run browser normally (visible) for debugging |
| `--debug` | Enable full debug mode (pause on failure, devtools) |
| `--slow-mo=<ms>` | Slow down browser actions by N milliseconds |
| `--sarif[=path]` | Output SARIF 2.1 report (optional path; defaults to reports/results.sarif) |
| `--policy=<path>` | Evaluate a specific policy YAML file during processing |
| `--compliance` | Enable compliance mapping (SOC2/GDPR/HIPAA) during report generation |
| `--target-type=<type>` | Target type: `web` (default), `electron` |
| `--electron-path=<path>` | Path to Electron executable (required when `--target-type=electron`) |
| `--electron-args=<args>` | Comma-separated args passed to Electron app |
| `--ai-fix[=model]` | Generate AI remediation via local Ollama (default model: `codellama`) |
| `--flutter-semantics` | Enable Flutter web semantics tree accessibility auditing |
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

## Electron App Auditing

Audit Electron desktop applications for security misconfigurations using Playwright's `electron.launch()` API.

```bash
npx ts-node src/index.ts --target-type=electron --electron-path=/path/to/your-app --profile=standard
```

Checks performed:
- `nodeIntegration` enabled in renderer (critical)
- `contextIsolation` disabled (critical)
- Remote module enabled (high)
- Missing Content Security Policy (medium)
- Exposed IPC channels (medium)

---

## Flutter Web Semantics Auditing

Automatically detect Flutter web builds and audit their accessibility semantics tree.

```bash
npx ts-node src/index.ts --flutter-semantics --profile=standard
```

The scanner detects Flutter via `flt-glass-pane`, `flutter_service_worker.js`, or `flt-semantics-host` and checks:
- Semantics tree presence (`flt-semantics-host` with children)
- ARIA attribute completeness on `flt-semantics` elements
- Focus management (at least one focusable semantic element)
- Live regions for dynamic content announcements

---

## Local LLM Remediation (Ollama)

Generate code-level fix suggestions for scan findings using a locally-hosted LLM via Ollama.

```bash
# Run scan then generate fixes with default model (codellama)
npx ts-node src/index.ts --profile=standard --ai-fix

# Use a specific model
npx ts-node src/index.ts --profile=standard --ai-fix=deepseek-coder
```

Prerequisites:
- [Ollama](https://ollama.ai) running locally on port 11434 (configurable via `OLLAMA_URL`)
- A code-oriented model pulled: `ollama pull codellama`

The service reads `fleet-summary.json` after scanning, extracts high/critical findings, and generates remediation suggestions written to `reports/ai-remediations.json`.

---

## Fintech Compliance Profile

Specialized scanning profile for financial and cryptocurrency applications.

```bash
npx ts-node src/index.ts --profile=fintech
```

Detection modules:
- **Crypto-jacking**: Known miner domains (coinhive, crypto-loot, etc.), mining pool WebSocket patterns, script content analysis for mining APIs
- **PCI-DSS**: Missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options), credit card numbers in localStorage/sessionStorage, payment form autocomplete attributes
- **Wallet Drainer**: Known drainer domains, Web3 wallet injection patterns (ethereum.request, solana), suspicious contract interaction scripts

Custom miner domains can be configured via `FINTECH_CUSTOM_MINER_DOMAINS` environment variable.

---

## Python Plugin Bridge

Write custom compliance checks in Python and run them alongside TypeScript/JavaScript checks.

Place Python scripts in `custom_checks/python/`:

```python
#!/usr/bin/env python3
import json, sys

context = json.loads(sys.argv[sys.argv.index('--context') + 1])
violations = []

# Your check logic here
for header_name in ['X-Frame-Options', 'Strict-Transport-Security']:
    if header_name not in context.get('headers', {}):
        violations.append({
            'id': f'missing-{header_name.lower()}',
            'severity': 'high',
            'message': f'Missing {header_name} header',
            'target': context.get('url', ''),
        })

print(json.dumps({'passed': len(violations) == 0, 'violations': violations}))
```

Enable Python checks in `.env`:

```bash
PYTHON_CHECKS_ENABLED=true
PYTHON_EXECUTABLE=python3
PYTHON_CHECK_TIMEOUT=30000
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and request features.

## 📄 License

MIT © [Cognostra](https://github.com/Cognostra)

## Disclaimer

This software is for authorized testing only. Do not run against targets without explicit permission.
