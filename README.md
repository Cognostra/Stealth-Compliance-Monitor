# Stealth Compliance Monitor

Automated security, performance, and accessibility auditing for web applications. Runs headless browser sessions through security proxies to detect vulnerabilities, measure Core Web Vitals, and verify WCAG compliance without disrupting production traffic.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Profiles](#scan-profiles)
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

---

## Scan Profiles

| Profile | Pages | Concurrency | Active Security | Use Case |
|---------|-------|-------------|-----------------|----------|
| `smoke` | 1 | 1 | No | Quick health check |
| `standard` | 15 | 3 | No | Regular CI/CD scans |
| `deep` | 50 | 5 | Yes | Full security assessment |

```bash
# Examples
npx ts-node src/index.ts --profile=smoke
npx ts-node src/index.ts --profile=standard
npx ts-node src/index.ts --profile=deep
```

The `deep` profile enables black-box penetration testing probes (IDOR, XSS, SQLi detection).

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
| `npm run clean` | Remove dist/ directory |

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

MIT

---

## Disclaimer

This software is for authorized testing only. Do not run against targets without explicit permission.
