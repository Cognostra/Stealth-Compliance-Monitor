# Stealth Compliance Monitor

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/Cognostra/Stealth-Compliance-Monitor?style=flat-square&logo=github)](https://github.com/Cognostra/Stealth-Compliance-Monitor/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![CI Status](https://img.shields.io/github/actions/workflow/status/Cognostra/Stealth-Compliance-Monitor/ci.yml?branch=main&style=flat-square&logo=github-actions&label=CI)](https://github.com/Cognostra/Stealth-Compliance-Monitor/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/Cognostra/Stealth-Compliance-Monitor?style=flat-square&logo=github)](https://github.com/Cognostra/Stealth-Compliance-Monitor/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/cognostra/stealth-compliance-monitor?style=flat-square&logo=docker)](https://hub.docker.com/r/cognostra/stealth-compliance-monitor)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square&logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://github.com/Cognostra/Stealth-Compliance-Monitor/blob/main/CONTRIBUTING.md)

**Enterprise-grade web compliance and security auditing platform**

[📖 Documentation](https://cognostra.github.io/Stealth-Compliance-Monitor/) · [🎮 Demo Guide](docs/demo-guide.md) · [🔌 Plugins](plugins/README.md) · [🐛 Report Bug](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=bug_report.md) · [✨ Request Feature](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=feature_request.md) · [💬 Discussions](https://github.com/Cognostra/Stealth-Compliance-Monitor/discussions)

</div>

---

Automated security, performance, and accessibility auditing for web applications. Runs headless browser sessions through security proxies to detect vulnerabilities, measure Core Web Vitals, and verify WCAG compliance without disrupting production traffic.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Profiles](#scan-profiles)
- [Debug Mode](#debug-mode)
- [Custom Compliance Checks](#custom-compliance-checks)
- [Plugin Gallery](#plugin-gallery)
- [API Endpoint Testing](#api-endpoint-testing)
- [Vulnerability Intelligence](#vulnerability-intelligence)
- [Fleet Mode](#fleet-mode)
- [Enterprise Integration](#enterprise-integration)
- [Reports](#reports)
- [Architecture](#architecture)
- [Scripts](#scripts)
- [License](#license)

---

## Features

### Security Scanning

- **Passive Security Analysis** - Routes traffic through OWASP ZAP proxy to detect vulnerabilities without active exploitation
- **Secret Detection** - Scans JavaScript sources for leaked API keys, tokens, and credentials
- **PII/DLP Scanning** - Detects exposed SSNs, credit card numbers, and phone numbers
- **Supabase Security** - Checks for service_role key leaks, RLS bypass, and storage bucket exposure
- **Vulnerable Dependencies** - Identifies outdated JavaScript libraries with known CVEs
- **Black-Box Pentesting** - Safe IDOR, XSS, SQLi, and auth bypass probes (deep profile only)
- **Cookie Analysis** - Validates Secure, HttpOnly, and SameSite attributes

### Performance Auditing

- **Lighthouse Integration** - Captures Performance, Accessibility, SEO, and Best Practices scores
- **Core Web Vitals** - Tracks LCP, CLS, TBT, FCP, Speed Index, and TTI
- **Network Throttling** - Simulates Slow 3G conditions to test application resilience
- **Asset Validation** - Detects broken images, oversized resources, and 404 errors

### Accessibility Compliance

- **axe-core Integration** - WCAG 2.1 A/AA and Section 508 violation detection
- **Impact Severity** - Categorizes issues as critical, serious, moderate, or minor
- **Playwright Locators** - Copy-paste selectors for immediate debugging

### Visual Regression

- **Pixel-Level Comparison** - Detects layout regressions against baseline screenshots
- **Configurable Threshold** - Adjust sensitivity for expected UI changes
- **Diff Generation** - Visual diff images highlighting changed regions

### Reporting and Alerts

- **Interactive HTML Dashboard** - Filterable remediation grid with severity badges
- **Historical Trends** - Track compliance scores across runs
- **AI Remediation** - Optional LLM-generated code fixes for detected issues
- **Webhook Notifications** - Slack, Microsoft Teams, Discord, and Zapier integration
- **SIEM Forwarding** - ECS/OCSF structured logs for Splunk, Datadog, and Elastic

### Reliability

- **Crash Resilience** - Write-Ahead Logging (WAL) ensures partial recovery on interruption
- **Stealth Mode** - Bot detection bypass via User-Agent randomization and WebDriver masking
- **Human-Like Behavior** - Configurable delays between actions

---

## Requirements

- Node.js v18 or higher
- Docker (for OWASP ZAP proxy)
- Git

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourorg/stealth-compliance-monitor.git
cd stealth-compliance-monitor

# Install dependencies
npm install

# Install Playwright browsers
npx playwright install chromium

# Copy environment template
cp .env.example .env
```

---

## Configuration

Edit `.env` with your target and credentials:

```bash
# Required
LIVE_URL=https://your-app.com
TEST_EMAIL=test@example.com
TEST_PASSWORD=your_password

# Security Proxy (default: http://localhost:8080)
ZAP_PROXY_URL=http://localhost:8080

# Human-like delays (milliseconds)
MIN_DELAY_MS=2000
MAX_DELAY_MS=5000

# AI Remediation (optional)
ENABLE_AI=false
OPENAI_API_KEY=sk-...

# Webhooks (optional)
WEBHOOK_URL=https://hooks.slack.com/services/...
WEBHOOK_SECRET=your_hmac_secret
WEBHOOK_EVENTS=critical

# SIEM Integration (optional)
SIEM_ENABLED=false
SIEM_WEBHOOK_URL=https://http-intake.logs.datadoghq.com/...
SIEM_LOG_PATH=./logs/security-events.log
```

---

## Usage

### Start the Security Proxy

```bash
docker-compose up -d zaproxy
```

### Run a Scan

```bash
# Development mode (TypeScript)
npm run dev

# Production mode (compiled)
npm run build
npm start

# With specific profile
npx ts-node src/index.ts --profile=deep
```

### Stop the Proxy

```bash
docker-compose down
```

## Quick Start (Minimal Setup)

If you just want a fast smoke scan:

1. Set required env vars in .env:
  - LIVE_URL, TEST_EMAIL, TEST_PASSWORD
2. Install dependencies:
  - npm install
  - npx playwright install chromium
3. Run smoke profile:
  - npm start -- --profile=smoke

> ZAP is optional for passive scans. If ZAP is not running, ZAP-specific tests are skipped.

---

## Scan Profiles

| Profile | Pages | Concurrency | Active Security | Active Scan | Use Case |
|---------|-------|-------------|-----------------|-------------|----------|
| `smoke` | 1 | 1 | No | No | Quick health check |
| `standard` | 15 | 3 | No | No | Regular CI/CD scans |
| `deep` | 50 | 5 | Yes | No | Full passive assessment |
| `deep-active` | 50 | 3 | Yes | **Yes** | Full active vulnerability scan |

```bash
# Examples
npx ts-node src/index.ts --profile=smoke
npx ts-node src/index.ts --profile=standard
npx ts-node src/index.ts --profile=deep
npx ts-node src/index.ts --profile=deep-active  # Active scanning!
npx ts-node src/index.ts --active                # Shortcut for deep-active
```

### Active Scanning Mode

The `deep-active` profile and `--active` flag enable **ZAP Active Scanning**:

- **Spider Crawl**: Automatically discovers all URLs on the target
- **Active Vulnerability Scan**: Sends attack payloads to test for real vulnerabilities
- **Heavy Rate Limiting**: Built-in delays to reduce server load

> ⚠️ **WARNING: Active scanning is AGGRESSIVE and NOT stealthy!**
>
> - May trigger WAF/IDS/DDoS protection
> - May cause server load or instability
> - May appear as malicious activity in logs
> - **Only use with explicit authorization on systems you own**

Active scan results are separated from passive findings in the report.

#### Safety Guardrails (Required)

Active scans only run when **both** of the following are configured:

```bash
ACTIVE_SCAN_ALLOWED=true
ACTIVE_SCAN_ALLOWLIST=example.com
```

This prevents accidental scans on unauthorized targets.

## Capabilities Matrix

| Capability | Smoke | Standard | Deep | Deep-Active |
|---|---:|---:|---:|---:|
| Lighthouse (Perf/A11y) | ✅ | ✅ | ✅ | ✅ |
| Crawler + Content Validation | ✅ | ✅ | ✅ | ✅ |
| Accessibility (axe-core) | ✅ | ✅ | ✅ | ✅ |
| Passive ZAP Alerts | ✅ | ✅ | ✅ | ✅ |
| Custom Checks | ✅ | ✅ | ✅ | ✅ |
| Black‑Box Security Probes | ❌ | ❌ | ✅ | ✅ |
| Active ZAP Scanning | ❌ | ❌ | ❌ | ✅ |

---

## Debug Mode

Run the scanner in visible browser mode for troubleshooting and development.

### CLI Flags

```bash
# Run with visible browser window
npx ts-node src/index.ts --headed

# Slow down all browser actions (great for visual debugging)
npx ts-node src/index.ts --slow-mo=500

# Full debug mode (headed + devtools + pause on failures)
npx ts-node src/index.ts --debug

# Combine with other flags
npx ts-node src/index.ts --debug --profile=smoke --slow-mo=1000
```

### Debug Features

| Flag | Description |
|------|-------------|
| `--headed` | Run browser in visible mode instead of headless |
| `--slow-mo=<ms>` | Add delay between each browser action (milliseconds) |
| `--debug` | Enable full debug mode: headed + devtools + pause on failure + console capture |

### Environment Variables

You can also configure debug mode via `.env`:

```bash
# Enable headed mode
DEBUG_HEADED=true

# Slow down actions (ms)
DEBUG_SLOW_MO=500

# Open DevTools on browser launch
DEBUG_DEVTOOLS=true

# Pause execution on failures
DEBUG_PAUSE_ON_FAILURE=true

# Capture console logs on errors
DEBUG_CAPTURE_CONSOLE=true
```

### Error Capture

When `DEBUG_CAPTURE_CONSOLE=true`, the scanner automatically:

1. **Captures Screenshots** - Saves browser state when errors occur
2. **Logs Console Messages** - Records all console.log, warn, and error messages
3. **Preserves State** - Creates diagnostic artifacts in `screenshots/` directory

### Interactive Debugging

When `DEBUG_PAUSE_ON_FAILURE=true`, the scanner pauses after errors allowing you to:

- Inspect the browser state
- Check DevTools console
- Manually navigate to debug
- Press Enter in the terminal to continue

---

## Deterministic Mode (CI Stability)

Enable stable randomness to reduce flaky diffs:

```bash
DETERMINISTIC_MODE=true
DETERMINISTIC_SEED=42
```

## Troubleshooting

- **ZAP not available**: ZAP tests are skipped when proxy is down. Start with:
  - docker-compose up -d zaproxy
- **Playwright browser deps**: On CI, use `npx playwright install chromium --with-deps`.
- **Baseline drift**: Set `VISUAL_BASELINE_MAX_AGE_DAYS` and either refresh manually or enable `VISUAL_BASELINE_AUTO_APPROVE`.

---

## Custom Compliance Checks

You can add your own custom checks using TypeScript/JavaScript.

1. Enable custom checks in `.env`:

    ```bash
    CUSTOM_CHECKS_ENABLED=true
    CUSTOM_CHECKS_DIR=./custom_checks
    ```

2. Add check files to the `custom_checks` directory.

Example `cookie-banner.ts`:

```typescript
import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader';

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];
    if (!await page.$('#cookie-banner')) {
        violations.push({
            id: 'cookie-banner-missing',
            title: 'Cookie Consent Banner Missing',
            severity: 'high',
            description: 'Sites must show cookie consent.'
        });
    }
    return violations;
}
```

Checks are executed automatically during the scan if enabled.

---

## Plugin Gallery

Pre-built plugins for common compliance and security checks:

| Plugin | Description | Category |
|--------|-------------|----------|
| [GDPR Cookie Consent](plugins/examples/gdpr-cookie-consent.ts) | GDPR cookie banner compliance | Privacy |
| [Brand Consistency](plugins/examples/brand-consistency.ts) | Visual brand validation | UX |
| [Performance Budget](plugins/examples/performance-budget.ts) | Resource budget enforcement | Performance |
| [Form Validation](plugins/examples/form-validation.ts) | Form accessibility & UX | Accessibility |
| [Social Meta Tags](plugins/examples/social-meta-tags.ts) | Open Graph & Twitter Cards | SEO |

### Installing a Plugin

```bash
# Copy to your custom_checks directory
cp plugins/examples/gdpr-cookie-consent.ts custom_checks/

# Run scan - plugin loads automatically!
npm run dev
```

📖 **Full Documentation**: [Plugin Gallery](plugins/README.md) | [Development Guide](docs/plugin-development.md)

---

## API Endpoint Testing

Test backend APIs (REST/GraphQL) for security vulnerabilities.

### Enable API Testing

```bash
# .env
API_TESTING_ENABLED=true

# Optional: Path to OpenAPI/Swagger spec
API_SPEC_PATH=./openapi.json
# or URL
API_SPEC_PATH=https://your-app.com/swagger.json

# Optional: Additional endpoints to test (comma-separated)
API_ENDPOINTS=/api/users,/api/admin,/graphql
```

### Features

- **Endpoint Discovery**: Automatically loads endpoints from OpenAPI/Swagger specs
- **Auth Bypass Testing**: Tests if protected endpoints are accessible without authentication
- **Rate Limiting Detection**: Verifies rate limiting is in place
- **Error Disclosure**: Checks for stack traces and database errors in responses
- **HTTP Method Confusion**: Tests if endpoints accept unexpected HTTP methods
- **Parameter Pollution**: Tests for HTTP parameter pollution vulnerabilities
- **Common Endpoint Probing**: Tests for exposed sensitive endpoints (admin, debug, etc.)

### Supported Discovery Methods

1. **OpenAPI/Swagger**: Provide a spec file path or URL
2. **Network Interception**: Endpoints are automatically discovered during page crawling
3. **Manual Configuration**: Add specific endpoints via `API_ENDPOINTS`

All API requests are routed through the ZAP proxy for additional passive scanning.

---

## Vulnerability Intelligence

Enrich vulnerability findings with CVE details, CVSS scores, exploit availability, and remediation guidance.

### Enable Intelligence Enrichment

```bash
# .env
VULN_INTEL_ENABLED=true

# Optional: NVD API key for higher rate limits
NVD_API_KEY=your-nvd-api-key

# Enable exploit database cross-referencing
VULN_INTEL_EXPLOITS=true

# Enable CISA KEV catalog checking
VULN_INTEL_KEV=true

# Cache TTL in minutes (default 24 hours)
VULN_INTEL_CACHE_TTL=1440
```

### Features

| Feature | Description |
|---------|-------------|
| **CVE Mapping** | Maps library vulnerabilities to CVE IDs with descriptions |
| **CVSS Scoring** | Provides CVSS v3.1 base scores and severity ratings |
| **Exploit Intelligence** | Checks if public exploits exist (ExploitDB, Metasploit, GitHub) |
| **CISA KEV** | Flags vulnerabilities in the Known Exploited Vulnerabilities catalog |
| **Risk Scoring** | Calculates 1-100 risk score based on multiple factors |
| **Remediation Priority** | Ranks fixes by effort level and security impact |
| **Version Guidance** | Recommends specific upgrade versions |

### Enriched Output

Each vulnerability finding is enriched with:

```json
{
  "cveId": "CVE-2020-11022",
  "cvss": {
    "version": "3.1",
    "baseScore": 6.1,
    "severity": "MEDIUM",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
  },
  "exploit": {
    "available": true,
    "source": "PoC",
    "maturity": "proof-of-concept"
  },
  "knownExploitedVuln": false,
  "remediation": {
    "type": "upgrade",
    "description": "Upgrade jQuery to version 3.5.0 or later",
    "targetVersion": "3.5.0",
    "effort": "low",
    "priority": 7
  },
  "riskScore": 75,
  "riskFactors": ["Public exploit available", "Network-accessible"]
}
```

### Data Sources

- **NVD**: National Vulnerability Database for CVE details
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **Local Database**: Offline fallback for common vulnerabilities

---

## Fleet Mode

Scan multiple sites in a single run by providing a JSON file or comma-separated URLs.

### Option 1: JSON File

Create `targets.json`:

```json
{
  "targets": [
    "https://app1.example.com",
    "https://app2.example.com",
    "https://app3.example.com"
  ]
}
```

Set in `.env`:

```bash
LIVE_URL=targets.json
```

### Option 2: Comma-Separated

```bash
LIVE_URL=https://app1.example.com,https://app2.example.com
```

Fleet mode generates a unified dashboard comparing all sites.

---

## Enterprise Integration

### Webhook Notifications

Sends alerts to Slack, Teams, Discord, or any webhook endpoint.

```bash
WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxx
WEBHOOK_SECRET=optional_hmac_secret
WEBHOOK_EVENTS=critical  # or 'all'
```

### SIEM Log Forwarding

Structured JSON logs compatible with Splunk, Datadog, and Elastic.

```bash
SIEM_ENABLED=true
SIEM_WEBHOOK_URL=https://http-intake.logs.datadoghq.com/v1/input/xxx
SIEM_LOG_PATH=./logs/security-events.log
```

### Auth Token Bypass

Skip login flows by injecting session cookies directly:

```bash
AUTH_COOKIE_NAME=session_token
AUTH_TOKEN_VALUE=your_valid_session_token
```

---

## Reports

Reports are generated in the `reports/` directory:

| File | Description |
|------|-------------|
| `{domain}-audit-report.html` | Interactive HTML dashboard |
| `fleet-dashboard.html` | Multi-site comparison (fleet mode) |
| `history.json` | Historical trend data |
| `latest.json` | Raw JSON findings |

### Opening Reports

```bash
# Open the HTML dashboard in your browser
start reports/loadout-audit-report.html  # Windows
open reports/loadout-audit-report.html   # macOS
```

### Report Branding (White-Label)

Customize report appearance with your company branding:

```bash
# .env
# Company name displayed in reports
BRAND_COMPANY_NAME=Acme Security

# Logo URL (PNG/SVG, max 200x50px)
BRAND_LOGO_URL=https://acme.com/logo.svg

# Primary brand color (hex format)
BRAND_PRIMARY_COLOR=#0066cc

# External CSS for advanced customization
BRAND_CUSTOM_CSS_URL=https://acme.com/report-styles.css

# Custom footer text
BRAND_FOOTER_TEXT=© 2024 Acme Corp. Security Team

# Report title prefix
BRAND_REPORT_TITLE=Acme Security
```

This produces reports with:
- Your company logo in the header
- Custom color scheme
- Branded footer text
- Professional white-label appearance

---

## Architecture

```
src/
  index.ts              # Entry point and orchestration
  config/               # Environment and profile configuration
  core/                 # ComplianceRunner, UserFlowRunner
  services/             # All scanning and reporting services
    AuthService.ts      # Authentication handling
    BrowserService.ts   # Playwright wrapper with stealth
    CrawlerService.ts   # Page discovery and validation
    LighthouseService.ts
    ZapService.ts
    A11yScanner.ts
    SecretScanner.ts
    PiiScanner.ts
    SecurityAssessment.ts
    VisualSentinel.ts
    HtmlReportGenerator.ts
    WebhookService.ts
    SiemLogger.ts
    ...
  types/                # TypeScript definitions
  utils/                # Logger, throttle utilities
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system diagrams.

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Run with ts-node (development) |
| `npm run build` | Compile TypeScript to dist/ |
| `npm start` | Run compiled JavaScript |
| `npm run audit` | Run with --full-audit flag |
| `npm run lint` | ESLint check |
| `npm run typecheck` | TypeScript type checking |
| `npm run clean` | Remove dist/ directory |
| `npm test` | Run Jest unit tests |
| `npm run test:integration` | Run Playwright integration tests |
| `npm run test:browser` | Run browser-based tests |
| `npm run test:zap` | Run E2E tests with ZAP proxy |
| `npm run test:all` | Run all test suites |

---

## Testing

The project includes comprehensive tests using Jest and Playwright.

### Running Tests

```bash
# Unit tests (Jest)
npm test
npm run test:coverage

# Integration tests (Playwright)
npm run test:integration

# Browser tests
npm run test:browser

# E2E with ZAP (requires ZAP proxy running)
docker-compose up -d zaproxy
npm run test:zap

# All tests
npm run test:all
```

### CI/CD Pipeline

GitHub Actions workflows are configured for:

- **Linting & Type Checking** - Runs on every push/PR
- **Unit Tests** - Jest with coverage reporting
- **Integration Tests** - Playwright tests against example.com
- **E2E Tests with ZAP** - Full integration tests (main branch only)

---

## Security: ZAP API Key

For production deployments, secure your ZAP proxy with an API key:

### Secure Mode (Production)

```bash
# Generate a strong API key
export ZAP_API_KEY=$(openssl rand -hex 32)

# Add to .env
echo "ZAP_API_KEY=$ZAP_API_KEY" >> .env

# Start with API key
docker-compose up -d
```

### Development Mode (Local)

Leave `ZAP_API_KEY` empty or unset to disable API authentication:

```bash
# No API key = open access (dev mode)
docker-compose up -d zaproxy
```

### Cleanup Script

Prepare for public release by removing sensitive data and git history:

```bash
# Preview what will be deleted
.\scripts\nuke-and-reinit.ps1 -DryRun

# Execute cleanup
.\scripts\nuke-and-reinit.ps1
```

---

## Graceful Shutdown

If interrupted (Ctrl+C), the monitor hydrates progress from the Write-Ahead Log and generates a partial report automatically.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support the Project

If you find this project useful, consider supporting its development:

<a href="https://github.com/sponsors/Cognostra">
  <img src="https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?style=for-the-badge&logo=github-sponsors" alt="GitHub Sponsors">
</a>

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

- Read our [Code of Conduct](CODE_OF_CONDUCT.md)
- Check out [open issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
- Submit [bug reports](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=bug_report.md) or [feature requests](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues/new?template=feature_request.md)

---

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md). **Do not** open public issues for security concerns.

---

## Disclaimer

This software is for authorized testing only. Do not run against targets without explicit permission.
