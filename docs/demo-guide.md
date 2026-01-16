# Demo & Sandbox Guide

Try Stealth Compliance Monitor without any setup using our demo options.

## Quick Demo Options

### 1. Docker One-Liner

Run a quick scan against any public website:

```bash
docker run --rm \
  -e LIVE_URL=https://example.com \
  -e TEST_EMAIL=demo@example.com \
  -e TEST_PASSWORD=demo \
  -v $(pwd)/reports:/app/reports \
  ghcr.io/cognostra/stealth-compliance-monitor:latest
```

### 2. GitHub Actions Demo

Fork the repository and run the demo workflow:

1. Fork: https://github.com/Cognostra/Stealth-Compliance-Monitor
2. Go to **Actions** tab
3. Run **Demo Scan** workflow
4. Enter your target URL
5. Download the report artifact

### 3. Local Sandbox

```bash
# Clone and setup
git clone https://github.com/Cognostra/Stealth-Compliance-Monitor.git
cd Stealth-Compliance-Monitor
npm install
npx playwright install chromium

# Run against example.com (no auth needed)
echo "LIVE_URL=https://example.com
TEST_EMAIL=demo@example.com
TEST_PASSWORD=demo" > .env

npm run dev
```

---

## Sample Reports

View example reports to understand the output:

| Report Type | Description | Link |
|------------|-------------|------|
| Executive Dashboard | Full HTML report with all checks | [View Sample](reports/dashboard.html) |
| Fleet Dashboard | Multi-site comparison | [View Sample](reports/fleet-dashboard.html) |
| JSON Export | Raw findings data | [View Sample](reports/latest.json) |

---

## Test Targets

Safe websites you can scan for testing:

| Site | URL | Notes |
|------|-----|-------|
| Example.com | `https://example.com` | Minimal page, fast scan |
| HTTPBin | `https://httpbin.org` | Good for testing network checks |
| BadSSL | `https://badssl.com` | Test SSL/TLS checks |
| OWASP Juice Shop | `http://localhost:3000` | Vulnerable app for testing (run locally) |

### Running OWASP Juice Shop Locally

```bash
# Start Juice Shop (intentionally vulnerable)
docker run -d -p 3000:3000 bkimminich/juice-shop

# Scan it (use deep profile for security testing)
LIVE_URL=http://localhost:3000 npm run dev -- --profile=deep
```

---

## Interactive Demo Mode

Enable debug mode to watch the scanner in action:

```bash
# .env
DEBUG_HEADED=true      # See the browser window
DEBUG_SLOW_MO=500      # Slow down actions (ms)
DEBUG_DEVTOOLS=true    # Open DevTools

npm run dev
```

This opens a visible browser so you can see exactly what's being scanned.

---

## Scan Profiles Demo

Try different scan intensities:

```bash
# Quick smoke test (1 page, ~30 seconds)
npm run dev -- --profile=smoke

# Standard CI/CD scan (15 pages, ~2 minutes)
npm run dev -- --profile=standard

# Deep security scan (50 pages, ~10 minutes)
npm run dev -- --profile=deep
```

---

## Feature Demos

### Accessibility Check

```bash
# Scan WCAG compliance
LIVE_URL=https://www.w3.org/WAI/demos/bad/ npm run dev
```

This scans a purposely inaccessible demo site to see accessibility violations.

### Performance Budget

```bash
# Check a heavy site
LIVE_URL=https://www.apple.com npm run dev -- --profile=standard
```

### Cookie Consent (with GDPR plugin)

```bash
# Copy the GDPR plugin
cp plugins/examples/gdpr-cookie-consent.ts custom_checks/

# Scan a European site
LIVE_URL=https://www.bbc.com npm run dev
```

---

## API Demo

Test the webhook integration:

```bash
# Start a webhook receiver
npx webhook-relay &

# Configure webhook
echo "WEBHOOK_URL=http://localhost:9000/webhook
WEBHOOK_EVENTS=all" >> .env

npm run dev
```

---

## Docker Compose Demo

Full stack with ZAP proxy:

```bash
# Start everything
docker-compose up

# View reports
ls reports/
open reports/*-audit-report.html
```

---

## CI/CD Integration Demo

### GitHub Actions

```yaml
# .github/workflows/compliance-demo.yml
name: Compliance Demo
on: workflow_dispatch
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npx playwright install chromium
      - run: npm run dev
        env:
          LIVE_URL: https://example.com
          TEST_EMAIL: demo@example.com
          TEST_PASSWORD: demo
      - uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: reports/
```

### GitLab CI

```yaml
# .gitlab-ci.yml
compliance-scan:
  image: mcr.microsoft.com/playwright:v1.41.0-jammy
  script:
    - npm ci
    - npm run dev
  artifacts:
    paths:
      - reports/
```

---

## Playground Environment

We're working on a hosted playground! Coming soon:

- 🌐 **Web Interface** - Paste a URL and get results
- 🔑 **API Access** - REST API for integration testing
- 📊 **Dashboard** - View historical scan data

Stay tuned: [Join our Discord](https://discord.gg/example) for updates!

---

## Video Tutorials

| Topic | Duration | Link |
|-------|----------|------|
| Getting Started | 5 min | Coming Soon |
| Custom Plugins | 10 min | Coming Soon |
| CI/CD Integration | 8 min | Coming Soon |
| Enterprise Setup | 15 min | Coming Soon |

---

## Need Help?

- 💬 [GitHub Discussions](https://github.com/Cognostra/Stealth-Compliance-Monitor/discussions)
- 📖 [Full Documentation](../README.md)
- 🐛 [Report Issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
