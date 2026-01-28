# Product Requirements Document

# Stealth Compliance Monitor
### Automated Live-Site Security & Compliance Auditing Platform

**Version 3.0 (Refactored)**
**January 2026**

---

## Executive Summary

Stealth Compliance Monitor (LSCM) is a **browser-based automated testing platform** that performs security, performance, and accessibility audits on **live web applications**. Unlike static code analysis tools, LSCM navigates production websites as a real user, routing all traffic through security proxies to detect vulnerabilities without disrupting service.

The tool combines:
- **Passive Security Scanning** (OWASP ZAP proxy analysis)
- **Performance Auditing** (Lighthouse Core Web Vitals)
- **Accessibility Testing** (axe-core WCAG 2.1 compliance)
- **Black-Box Penetration Testing** (IDOR, XSS, SQLi probes)
- **Visual Regression Detection** (pixel-level layout comparison)
- **Secret & PII Detection** (API keys, credentials, SSNs, credit cards)

This PRD outlines the roadmap for evolving LSCM from its current state (v2.0) to an enterprise-grade continuous monitoring platform with enhanced compliance frameworks, advanced pentesting capabilities, distributed scanning, and real-time alerting.

---

## Strategic Positioning

**Strategic Differentiation**

Unlike SAST tools (Semgrep, SonarQube) or DAST tools (Burp Suite, Acunetix) that require either source code or manual configuration, Stealth Compliance Monitor is the **"Synthetic Monitoring for Security"** - it tests applications from the user's perspective with zero application modifications required.

**Key Differentiators:**
- **Zero-Touch Deployment**: No agents, no SDK, no code changes - just point at a URL
- **Production-Safe**: Read-only operations with human-like delays prevent service disruption
- **Multi-Dimensional**: Combines security (ZAP), performance (Lighthouse), accessibility (axe-core), and visual regression in one scan
- **Stealth Mode**: Evades bot detection via User-Agent randomization and WebDriver masking
- **Compliance-Native**: Generates SOC2/GDPR/WCAG evidence packages automatically
- **Developer-Friendly**: Interactive HTML dashboards with copy-paste Playwright selectors for immediate debugging

**Competitive Landscape:**

| Feature | LSCM | Burp Suite | Lighthouse | Synthetic Monitoring (Datadog) |
|---------|------|------------|------------|--------------------------------|
| **Security Scanning** | ✅ Passive + Active | ✅ Manual + Active | ❌ | ⚠️ Limited |
| **Performance Auditing** | ✅ Lighthouse | ❌ | ✅ | ✅ Uptime only |
| **Accessibility (A11y)** | ✅ axe-core | ❌ | ✅ Lighthouse | ❌ |
| **Visual Regression** | ✅ Pixel diff | ❌ | ❌ | ⚠️ Screenshots only |
| **Automated Crawling** | ✅ Smart discovery | ⚠️ Manual | ❌ | ❌ |
| **Fleet Mode** | ✅ Multi-site | ❌ | ❌ | ✅ |
| **Stealth/Evasion** | ✅ Built-in | ⚠️ Manual config | ❌ | ❌ |
| **Compliance Reports** | ✅ SOC2/GDPR/WCAG | ❌ | ⚠️ A11y only | ❌ |
| **Pricing** | Open-source (MIT) | $449-$1,299/user/year | Free | $15/10K tests |

---

## Product Vision

To become the **industry-standard platform for continuous compliance monitoring** of web applications, enabling organizations to maintain security, performance, and accessibility posture in production environments without disrupting user experience.

---

## Target Users

- **Security Engineers** performing regular penetration testing and vulnerability assessments
- **QA Teams** automating regression testing and cross-browser compliance checks
- **DevOps/SRE** monitoring production health and performance degradation
- **Compliance Officers** generating SOC2, GDPR, WCAG audit evidence
- **MSPs/Consultancies** managing security posture for multiple client applications
- **Enterprise IT** enforcing organization-wide security and accessibility policies

---

## Current State Analysis (v2.0)

### What Exists Today ✅

Based on analysis of the actual codebase ([ARCHITECTURE.md](ARCHITECTURE.md), [README.md](README.md), `src/`), here's what's **already built and working**:

#### Core Browser Engine
- **Playwright Integration**: Chromium browser automation with stealth mode
- **ZAP Proxy**: All HTTP/HTTPS traffic routed through OWASP ZAP (localhost:8080)
- **Stealth Evasion**: `navigator.webdriver` removal, User-Agent randomization, viewport randomization
- **Human-Like Delays**: Configurable MIN_DELAY_MS/MAX_DELAY_MS between actions

#### Security Scanning (Comprehensive)
- ✅ **Passive ZAP Alerts**: Vulnerabilities detected from proxied traffic
- ✅ **Active ZAP Scanning**: Spider crawl + attack payloads (guarded by ACTIVE_SCAN_ALLOWED + allowlist)
- ✅ **Secret Detection**: [SecretScanner.ts](src/services/SecretScanner.ts) - API keys, tokens, AWS credentials in JS sources
- ✅ **PII/DLP Scanning**: [PiiScanner.ts](src/services/PiiScanner.ts) - SSN, credit cards, phone numbers with redaction
- ✅ **Supabase Security**: [SupabaseSecurityScanner.ts](src/services/SupabaseSecurityScanner.ts) - service_role key leaks, RLS bypass, storage bucket exposure
- ✅ **Vulnerable Libraries**: [FrontendVulnerabilityScanner.ts](src/services/FrontendVulnerabilityScanner.ts) - Detects jQuery, Lodash, Angular versions with CVE matching
- ✅ **Cookie Security**: Validates Secure, HttpOnly, SameSite attributes
- ✅ **Black-Box Pentesting**: [SecurityAssessment.ts](src/services/SecurityAssessment.ts) - IDOR (ID mutation), XSS (safe payloads), SQLi (error/time-based), auth bypass, rate limiting
- ✅ **API Endpoint Testing**: [ApiEndpointTester.ts](src/services/ApiEndpointTester.ts) - REST/GraphQL auth bypass, rate limiting, error disclosure, HTTP method confusion

#### Performance & Accessibility
- ✅ **Lighthouse Integration**: [LighthouseService.ts](src/services/LighthouseService.ts) - Performance, Accessibility, SEO, Best Practices scores
- ✅ **Core Web Vitals**: LCP, CLS, TBT, FCP, Speed Index, TTI tracking
- ✅ **Network Throttling**: Slow 3G simulation
- ✅ **axe-core**: [A11yScanner.ts](src/services/A11yScanner.ts) - WCAG 2.1 A/AA violation detection with impact severity
- ✅ **Playwright Locators**: Copy-paste selectors for immediate debugging

#### Content Validation
- ✅ **Intelligent Crawler**: [CrawlerService.ts](src/services/CrawlerService.ts) - Priority keyword discovery (settings, admin, profile, dashboard)
- ✅ **Asset Validation**: [AssetValidator.ts](src/services/AssetValidator.ts) - Broken images, oversized resources, 404s
- ✅ **Link Checker**: [LinkChecker.ts](src/services/LinkChecker.ts) - Internal/external broken links
- ✅ **SEO Validator**: [SEOValidator.ts](src/services/SEOValidator.ts) - Meta tags, Open Graph, schema.org, sitemap
- ✅ **Visual Regression**: [VisualSentinel.ts](src/services/VisualSentinel.ts) - Pixel-level baseline comparison with configurable threshold

#### Reporting & Integration
- ✅ **Interactive HTML Dashboard**: [HtmlReportGenerator.ts](src/services/HtmlReportGenerator.ts) - Filterable remediation grid, severity badges, historical trends
- ✅ **Fleet Dashboard**: [FleetReportGenerator.ts](src/services/FleetReportGenerator.ts) - Multi-site comparison
- ✅ **AI Remediation**: [AiRemediationService.ts](src/services/AiRemediationService.ts) - OpenAI GPT-4 code fix generation
- ✅ **Webhook Notifications**: [WebhookService.ts](src/services/WebhookService.ts) - Slack, Teams, Discord, Zapier with HMAC signing
- ✅ **SIEM Logging**: [SiemLogger.ts](src/services/SiemLogger.ts) - ECS/OCSF structured logs for Splunk, Datadog, Elastic
- ✅ **Historical Tracking**: [HistoryService.ts](src/services/HistoryService.ts) - Trend analysis over time

#### Enterprise Features
- ✅ **Fleet Mode**: Scan multiple sites via `LIVE_URL=targets.json` or comma-separated URLs
- ✅ **Custom Checks**: [CustomCheckLoader.ts](src/core/CustomCheckLoader.ts) - TypeScript plugin system
- ✅ **Write-Ahead Logging**: [PersistenceService.ts](src/services/PersistenceService.ts) - Crash recovery with JSONL
- ✅ **White-Label Branding**: BRAND_COMPANY_NAME, BRAND_LOGO_URL, BRAND_PRIMARY_COLOR
- ✅ **Auth Token Bypass**: Inject session cookies (AUTH_COOKIE_NAME, AUTH_TOKEN_VALUE)
- ✅ **Deterministic Mode**: Stable randomness for CI (DETERMINISTIC_MODE + seed)
- ✅ **Vulnerability Intelligence**: [VulnIntelligenceService.ts](src/services/VulnIntelligenceService.ts) - CVE mapping, CVSS scoring, exploit availability, CISA KEV check

#### Scan Profiles
- ✅ `smoke`: 1 page, quick check (< 2 min)
- ✅ `standard`: 15 pages, CI/CD (< 10 min)
- ✅ `deep`: 50 pages, full passive (< 30 min)
- ✅ `deep-active`: 50 pages, ZAP spider + active (< 60 min)

#### CLI & Debug
- ✅ `--profile=<name>`: Select scan profile
- ✅ `--active`: Enable active scanning
- ✅ `--headed`: Run browser visibly
- ✅ `--slow-mo=<ms>`: Slow down actions
- ✅ `--debug`: Full debug mode (headed + devtools + pause on failure)

### What's Missing (Gap Analysis)

Comparing current state to typical enterprise needs:

❌ **Not Built:**
- Source code analysis (SAST) - LSCM is black-box only
- CI/CD pipeline integration (GitHub Actions, GitLab CI)
- Continuous scheduled monitoring (cron-based)
- Distributed worker architecture for scale
- Web dashboard (all reporting is file-based)
- Database storage (currently JSON files)
- Compliance framework mapping (SOC2, GDPR, HIPAA)
- Policy-as-code engine
- SARIF output for GitHub Code Scanning
- Multi-browser support (only Chromium)

---

## Feature Roadmap (v3.0 → v5.0)

### Phase 1: CI/CD & Compliance (Months 1-3)

#### 1.1 GitHub Actions Integration

| Priority | P0 - Critical |
|----------|---------------|
| **Description** | Official GitHub Action for running LSCM in CI/CD pipelines |
| **User Stories** | • As a developer, I want security scans on every PR<br>• As a team lead, I want to block merges when HIGH findings exist |
| **Implementation** | Create `stealth-compliance-monitor/action` repo with `action.yml`:<br>```yaml<br>- uses: stealth-monitor/action@v3<br>  with:<br>    url: ${{ secrets.STAGING_URL }}<br>    profile: standard<br>    fail-on: high  # critical, high, medium, low<br>```<br>• Upload HTML report as artifact<br>• Post PR comment with summary<br>• Support SARIF upload for Code Scanning tab<br>• Exit code 1 if findings exceed threshold |
| **Files Affected** | New repo, integrate with existing ComplianceRunner.ts |

#### 1.2 Compliance Framework Mapping (SOC2/GDPR/HIPAA)

| Priority | P0 - Critical |
|----------|---------------|
| **Description** | Map findings to compliance control requirements for audit evidence |
| **User Stories** | • As a compliance officer, I want SOC2 CC6.1 evidence automatically<br>• As an auditor, I want to see which controls are failing |
| **Implementation** | Create `src/data/compliance-frameworks.ts`:<br>```typescript<br>export const complianceMap = {<br>  soc2: {<br>    'CC6.1': { // Logical Access Controls<br>      checks: ['auth-bypass', 'idor', 'csrf'],<br>      description: 'Access restricted to authorized users'<br>    },<br>    'CC6.6': { // Vulnerability Management<br>      checks: ['vulnerable-library', 'zap-high', 'xss', 'sqli'],<br>      description: 'Vulnerabilities identified and addressed'<br>    }<br>  },<br>  gdpr: {<br>    'Art32': { // Security of Processing<br>      checks: ['cookie-security', 'pii-exposure', 'secrets'],<br>      description: 'Appropriate technical measures'<br>    }<br>  },<br>  hipaa: {<br>    '164.312': { // Technical Safeguards<br>      checks: ['encryption-in-transit', 'auth-bypass'],<br>      description: 'Access control mechanisms'<br>    }<br>  }<br>};<br>```<br>• Enrich findings with `complianceMappings: [{framework, controls}]`<br>• Generate compliance-specific reports |
| **Files Affected** | src/data/compliance-frameworks.ts (new), src/types/index.ts, HtmlReportGenerator.ts |

#### 1.3 Policy-as-Code Engine

| Priority | P1 - High |
|----------|---------------|
| **Description** | Define custom pass/fail rules in YAML configuration |
| **User Stories** | • As a security engineer, I want to fail builds if `/admin` is publicly accessible<br>• As a team lead, I want to enforce "no critical findings" |
| **Implementation** | Support `.compliance-policy.yml` in project root:<br>```yaml<br>policies:<br>  - name: "No public admin access"<br>    condition: "url contains '/admin' AND status_code == 200"<br>    severity: critical<br>    action: fail<br><br>  - name: "No critical vulnerabilities"<br>    condition: "severity == 'critical'"<br>    action: fail<br>    message: "Critical vulnerabilities block deployment"<br><br>  - name: "Performance budget"<br>    condition: "lighthouse_performance < 80"<br>    action: warn<br>```<br>• Simple expression parser (no eval, use safe AST)<br>• Evaluate policies post-scan in ComplianceRunner<br>• Override exit code based on policy results |
| **Files Affected** | src/config/policy-loader.ts (new), src/core/PolicyEngine.ts (new), ComplianceRunner.ts |

#### 1.4 SARIF Output for GitHub Code Scanning

| Priority | P1 - High |
|----------|---------------|
| **Description** | Export findings in SARIF 2.1 format for GitHub Security tab |
| **User Stories** | • As a developer, I want security findings in GitHub's Security tab<br>• As a security team, I want unified SAST + DAST view |
| **Implementation** | Create `src/services/SarifReporter.ts`:<br>• Map findings to SARIF schema:<br>  - `tool.driver.name` = "Stealth Compliance Monitor"<br>  - `results[].ruleId` = finding ID<br>  - `results[].locations[].physicalLocation.artifactLocation.uri` = URL (map to pseudo-file)<br>  - `results[].level` = error/warning/note<br>• **Challenge**: SARIF expects file:line, but LSCM has URL:selector<br>  - Map URL → pseudo-file: `https://example.com/page` → `example.com/page.html`<br>  - Map Playwright selector → line: hash selector to consistent line number<br>• Upload via GitHub API: `POST /repos/{owner}/{repo}/code-scanning/sarifs` |
| **Files Affected** | src/services/SarifReporter.ts (new), src/types/sarif.ts (new), index.ts |

---

### Phase 2: Scale & Automation (Months 4-6)

#### 2.1 Continuous Monitoring (Scheduled Scans)

| Priority | P1 - High |
|----------|---------------|
| **Description** | Run scans on schedule (hourly, daily, weekly) with alerting |
| **User Stories** | • As a DevOps engineer, I want hourly smoke tests to catch production issues<br>• As a security engineer, I want daily deep scans with Slack alerts |
| **Implementation** | • **Scheduler**: Integrate with system cron or cloud schedulers (AWS EventBridge, GCP Scheduler)<br>• Store config in `monitoring-schedule.yml`:<br>```yaml<br>schedules:<br>  - name: "Production smoke test"<br>    url: https://app.example.com<br>    profile: smoke<br>    cron: "0 * * * *"  # Hourly<br>    alert_on: new_findings  # or always, never<br><br>  - name: "Full security audit"<br>    url: https://app.example.com<br>    profile: deep<br>    cron: "0 2 * * *"  # Daily 2 AM<br>    alert_on: regressions<br>```<br>• Compare against baseline (BaselineService)<br>• Alert only on delta (new findings or regressions)<br>• **Alert fatigue prevention**: Suppress repeat findings<br>• Track finding `first_seen` and `last_seen` timestamps |
| **Files Affected** | src/scheduler/CronScheduler.ts (new), src/scheduler/monitoring-schedule.yml (new), BaselineService.ts |

#### 2.2 Distributed Worker Architecture

| Priority | P2 - Medium |
|----------|---------------|
| **Description** | Scale to 1000+ sites with worker pool and job queue |
| **User Stories** | • As an MSP, I want to scan 500 client sites in parallel<br>• As an enterprise, I want to distribute load across multiple servers |
| **Implementation** | **Architecture**:<br>```<br>┌────────────┐<br>│ Coordinator│  (Job scheduler, load balancer)<br>└─────┬──────┘<br>      │<br>      ▼<br>┌────────────┐<br>│Redis Queue │  (Scan jobs, priority queue)<br>└─────┬──────┘<br>      │<br>   ┌──┴──┬──────┬──────┐<br>   ▼     ▼      ▼      ▼<br>Worker Worker Worker Worker<br>(ComplianceRunner instances)<br>```<br>• **Coordinator**: `src/coordinator/JobScheduler.ts`<br>  - Accept job submissions via REST API<br>  - Enqueue jobs to Redis with priority<br>  - Track worker health/registration<br>• **Worker**: Existing ComplianceRunner + job pulling logic<br>  - Poll queue for jobs<br>  - Execute scan<br>  - POST results to coordinator<br>• **API**: Express REST endpoints<br>```<br>POST /api/v1/scans - Submit scan job<br>GET /api/v1/scans/:id/status - Check status<br>GET /api/v1/scans/:id/results - Get report<br>```<br>• **Storage**: TimescaleDB for results (time-series optimized) |
| **Files Affected** | src/coordinator/ (new package), src/worker/ (new package), docker-compose-distributed.yml (new) |

#### 2.3 Fleet Mode Enhancements

| Priority | P1 - High |
|----------|---------------|
| **Description** | Parallel execution and advanced comparison for multi-site scans |
| **Current State** | Sequential scans; basic comparison dashboard |
| **User Stories** | • As an MSP, I want to scan 100 sites in parallel (not sequential)<br>• As a compliance officer, I want to rank sites by security score |
| **Implementation** | • Use `p-limit` (already in package.json) for concurrency control:<br>```typescript<br>import pLimit from 'p-limit';<br>const limit = pLimit(10); // Max 10 concurrent scans<br>const results = await Promise.all(<br>  urls.map(url => limit(() => scanSite(url)))<br>);<br>```<br>• **Fleet Report Enhancements** (FleetReportGenerator.ts):<br>  - Rank sites by overall score<br>  - Identify common vulnerabilities (appears in >50% of sites)<br>  - "Worst performers" table<br>  - Export as CSV for Excel analysis<br>• **Fleet Dashboard UI**: React table with sorting, filtering, search |
| **Files Affected** | src/services/FleetReportGenerator.ts, src/core/ComplianceRunner.ts (add parallel mode) |

#### 2.4 Performance Budgets & Regression Alerts

| Priority | P1 - High |
|----------|---------------|
| **Description** | Fail scans when Lighthouse scores or Core Web Vitals exceed thresholds |
| **User Stories** | • As a product manager, I want builds to fail if LCP > 2.5s<br>• As a developer, I want to catch performance regressions before deployment |
| **Implementation** | • Add to `.env` or `.compliance-policy.yml`:<br>```bash<br>PERFORMANCE_BUDGET_LCP=2500  # ms<br>PERFORMANCE_BUDGET_FID=100<br>PERFORMANCE_BUDGET_CLS=0.1<br>LIGHTHOUSE_MIN_PERFORMANCE=80<br>LIGHTHOUSE_MIN_ACCESSIBILITY=95<br>```<br>• In LighthouseService.ts, compare against budgets:<br>```typescript<br>if (metrics.lcp > config.PERFORMANCE_BUDGET_LCP) {<br>  violations.push({<br>    severity: 'high',<br>    title: `LCP exceeds budget: ${metrics.lcp}ms > ${budget}ms`,<br>    action: 'fail'<br>  });<br>}<br>```<br>• Compare current scan vs. baseline (HistoryService integration)<br>• Exit code 1 if budget exceeded<br>• Alert via webhooks on regression |
| **Files Affected** | src/services/LighthouseService.ts, src/config/env.ts, ComplianceRunner.ts |

---

### Phase 3: Advanced Security (Months 7-9)

#### 3.1 Advanced Pentest Modules

| Priority | P1 - High |
|----------|---------------|
| **Description** | Expand black-box testing to cover OWASP Top 10 comprehensively |
| **Current State** | IDOR, XSS, SQLi, auth bypass basics exist in SecurityAssessment.ts |
| **User Stories** | • As a pentester, I want to test for SSRF in file uploads<br>• As a security engineer, I want XXE detection in XML endpoints |
| **Implementation** | Enhance SecurityAssessment.ts with:<br>• **SSRF Testing**: Submit URLs to upload/import forms<br>  - Payloads: `http://169.254.169.254/`, `http://metadata.google.internal`<br>  - Detect: Response contains cloud metadata<br>• **XXE Detection**: Submit XML with external entity references<br>  - Payload: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`<br>  - Detect: Response time anomaly or file content leakage<br>• **CSRF Validation**: Test if forms accept requests without CSRF tokens<br>  - Submit forms without referer/CSRF token<br>  - Detect: Success response (200 OK)<br>• **Insecure Deserialization**: Detect Java/Python/PHP serialization patterns<br>  - Payload: Malformed serialized objects<br>  - Detect: Error messages revealing deserialization<br>• **Path Traversal**: Test file upload endpoints<br>  - Payload: `../../../etc/passwd`, `..\\..\\..\\windows\\system32\\`<br>  - Detect: File path in response or access to unexpected files<br>• **Command Injection**: Time-based detection<br>  - Payloads: `; sleep 10 #`, `| ping -n 10 127.0.0.1`<br>  - Detect: Response delay matching payload |
| **Files Affected** | src/services/SecurityAssessment.ts (expand), src/types/pentest.ts (new) |

#### 3.2 API Security Testing (OpenAPI Fuzzing)

| Priority | P1 - High |
|----------|---------------|
| **Description** | Schema-based fuzzing and comprehensive REST/GraphQL testing |
| **Current State** | Basic auth bypass and rate limiting in ApiEndpointTester.ts |
| **User Stories** | • As an API developer, I want to validate my OpenAPI spec matches reality<br>• As a security engineer, I want to fuzz all parameters automatically |
| **Implementation** | Enhance ApiEndpointTester.ts with:<br>• **OpenAPI Spec Parsing**: Load from file or URL<br>  - Parse endpoints, methods, parameters, schemas<br>  - Generate test cases for each endpoint<br>• **Schema-Based Fuzzing**:<br>  - String params → XSS payloads (`<script>`, `${7*7}`)<br>  - Integer params → Overflow (MAX_INT, negative)<br>  - Array params → Large arrays, empty arrays<br>  - Object params → Missing required fields, extra fields<br>• **BOLA Testing** (Broken Object Level Authorization):<br>  - ID mutation: `/api/users/123` → `/api/users/124`<br>  - Detect: Unauthorized access to other users' data<br>• **Response Schema Validation**: Compare actual response vs. spec<br>  - Fail if schema mismatch (e.g., missing required fields)<br>• **GraphQL Testing**:<br>  - Introspection query for schema discovery<br>  - Mutation fuzzing with invalid inputs<br>  - Nested query depth bomb detection |
| **Files Affected** | src/services/ApiEndpointTester.ts (major enhancement), src/types/openapi.ts (new) |

#### 3.3 Supply Chain Security (SRI & CDN Integrity)

| Priority | P2 - Medium |
|----------|---------------|
| **Description** | Detect missing Subresource Integrity (SRI) hashes and compromised third-party scripts |
| **User Stories** | • As a security engineer, I want to know if CDN scripts lack SRI protection<br>• As a developer, I want to detect unexpected script changes from third-party CDNs |
| **Implementation** | Create `src/services/SupplyChainScanner.ts`:<br>• **SRI Validation**:<br>  - Intercept all `<script src="https://cdn...">` and `<link rel="stylesheet">`<br>  - Check for `integrity="sha384-..."` attribute<br>  - Alert if missing<br>• **Resource Integrity Verification**:<br>  - Fetch external resources<br>  - Hash content (SHA-384/SHA-512)<br>  - Compare against known-good baseline<br>  - Alert on hash mismatch (potential compromise)<br>• **Automatic SRI Generation**:<br>  - Generate `integrity` attributes for unprotected resources<br>  - Include in report as remediation guidance<br>• **CDN Availability Check**:<br>  - Test if CDN is reachable<br>  - Alert if resource fails to load |
| **Files Affected** | src/services/SupplyChainScanner.ts (new), BrowserService.ts (integrate resource interception) |

---

### Phase 4: Reporting & UX (Months 10-12)

#### 4.1 Enhanced HTML Dashboard

| Priority | P1 - High |
|----------|---------------|
| **Description** | Advanced filtering, search, and export capabilities |
| **Current State** | Basic interactive dashboard with severity badges |
| **User Stories** | • As a QA engineer, I want to filter findings by page URL<br>• As a manager, I want to export findings to CSV for Excel |
| **Implementation** | Enhance HtmlReportGenerator.ts with:<br>• **Advanced Filters**:<br>  - By severity: Critical, High, Medium, Low<br>  - By category: Security, Performance, Accessibility, Content<br>  - By scanner: ZAP, Lighthouse, axe-core, Custom<br>  - By page URL: Dropdown of scanned pages<br>  - By status: New, Recurring, Resolved<br>• **Full-Text Search**: Across titles, descriptions, selectors<br>• **Sort Options**: By severity, date detected, remediation effort<br>• **Export**:<br>  - CSV: All findings with columns<br>  - JSON: Raw data for API consumers<br>  - PDF: Executive summary (via Puppeteer)<br>• **Dark Mode**: Respect `prefers-color-scheme: dark`<br>• **Mobile-Responsive**: Works on tablets for field reviews<br>• **Permalink**: Share URLs to specific findings (#finding-abc123) |
| **Files Affected** | src/services/HtmlReportGenerator.ts (enhance templates), templates/dashboard.html |

#### 4.2 Executive Summary Dashboard

| Priority | P2 - Medium |
|----------|---------------|
| **Description** | Generate separate 1-page executive PDF |
| **User Stories** | • As a CISO, I want a 1-page summary for board meetings<br>• As an executive, I want trend charts showing improvement |
| **Implementation** | Create `src/services/ExecutiveReportGenerator.ts`:<br>• **Content**:<br>  - Overall Security Score: 0-100 (weighted by severity)<br>  - Critical/High Counts: With trend arrows (↑↓)<br>  - Compliance Status: SOC2/GDPR pass/fail badges<br>  - Top 3 Risks: Most critical findings<br>  - Top 3 Improvements: Recently resolved issues<br>• **Charts** (via Chart.js or D3.js):<br>  - Score trend: Line chart (last 30 days)<br>  - Findings by category: Pie chart<br>  - Resolution velocity: Bar chart (issues fixed per week)<br>• **Format**: PDF generated with Puppeteer<br>  - Render HTML → PDF<br>  - White-label branding (BRAND_LOGO_URL, colors)<br>• **Delivery**: Email via SMTP or S3 upload |
| **Files Affected** | src/services/ExecutiveReportGenerator.ts (new), templates/executive-summary.html (new) |

#### 4.3 CLI Improvements

| Priority | P1 - High |
|----------|---------------|
| **Description** | Interactive wizard, progress bars, better errors |
| **Current State** | Basic CLI with flags; no interactivity |
| **User Stories** | • As a developer, I want an interactive setup wizard<br>• As a user, I want real-time progress updates |
| **Implementation** | • **Interactive Init**: `stealth-monitor init`<br>  - Use `inquirer` or `clack` for prompts<br>  - Generate `.env` from answers<br>  - Test connection to target URL<br>  - Offer to start first scan<br>• **Progress Bars**: Use `cli-progress`<br>```typescript<br>const bar = new cliProgress.SingleBar({<br>  format: 'Scanning [{bar}] {percentage}% | {value}/{total} pages'<br>});<br>bar.start(totalPages, 0);<br>// Update as pages are scanned<br>bar.update(currentPage);<br>bar.stop();<br>```<br>• **Better Error Messages**:<br>  - **Error**: "ZAP proxy not reachable at localhost:8080"<br>  - **Action**: "Run: docker-compose up -d zaproxy"<br>  - Color-coded (red for errors, yellow for warnings)<br>• **JSON Output**: `--output=json` for CI parsing<br>• **Quiet Mode**: `--quiet` for minimal output |
| **Files Affected** | src/index.ts (add interactive mode), src/utils/cli-helpers.ts (new) |

---

### Phase 5: Enterprise Features (Months 13-18)

#### 5.1 Web Dashboard (Optional SaaS)

| Priority | P3 - Low |
|----------|---------------|
| **Description** | Hosted web interface for managing scans and viewing results |
| **User Stories** | • As a manager, I want a web UI to view all scan results<br>• As a team, we want collaborative issue tracking |
| **Implementation** | **Tech Stack**:<br>- **Frontend**: Next.js (React) + TailwindCSS<br>- **Backend**: Express API + TimescaleDB<br>- **Auth**: NextAuth.js (OAuth, SAML for enterprise)<br>- **Real-time**: WebSockets for live scan progress<br><br>**Features**:<br>- Dashboard: Overview of all projects<br>- Scan Management: Schedule, run, cancel scans<br>- Results Viewer: Interactive findings browser<br>- Trend Charts: Historical performance/security metrics<br>- User Management: Teams, roles, permissions<br>- Integrations: Slack, Jira, PagerDuty<br><br>**Deployment**: Docker Compose or Kubernetes |
| **Files Affected** | New package: `packages/dashboard/` (separate from CLI) |

#### 5.2 Multi-Browser Support

| Priority | P3 - Low |
|----------|---------------|
| **Description** | Support Firefox and Safari (WebKit) alongside Chromium |
| **User Stories** | • As a QA engineer, I want to test cross-browser compatibility<br>• As a developer, I want to catch Safari-specific issues |
| **Implementation** | • Playwright already supports Firefox and WebKit<br>• Add `BROWSER` env var: chromium, firefox, webkit, all<br>• Run scans in parallel across browsers<br>• Generate browser-specific reports<br>• **Challenges**:<br>  - ZAP proxy configuration differs per browser<br>  - Some features may not work (e.g., stealth mode in Firefox)<br>  - Performance overhead (3x resources for "all") |
| **Files Affected** | src/services/BrowserService.ts (add browser selection), src/config/env.ts |

#### 5.3 Historical Compliance Tracking Dashboard

| Priority | P2 - Medium |
|----------|---------------|
| **Description** | Visualize compliance posture over time with drift alerts |
| **Current State** | HistoryService stores JSON; no compliance-specific tracking |
| **User Stories** | • As a compliance officer, I want to see when we fell out of SOC2 compliance<br>• As a security engineer, I want charts of vulnerability trends |
| **Implementation** | Enhance HistoryService.ts:<br>• **Data Model**:<br>```typescript<br>interface ComplianceSnapshot {<br>  timestamp: string;<br>  framework: 'soc2' | 'gdpr' | 'hipaa';<br>  compliant: boolean;<br>  score: number; // 0-100<br>  passingControls: string[];<br>  failingControls: string[];<br>  criticalCount: number;<br>  highCount: number;<br>}<br>```<br>• Store snapshots in `history/compliance-{framework}.json`<br>• Generate trend charts in HTML dashboard:<br>  - Compliance score over time (line chart)<br>  - Vulnerability counts by severity (area chart)<br>  - Time-to-remediation metrics (bar chart)<br>• **Drift Alerts**: Webhook notification when compliance status changes<br>  - "Project X fell out of SOC2 compliance (CC6.1 failure)" |
| **Files Affected** | src/services/HistoryService.ts, src/types/compliance.ts, HtmlReportGenerator.ts (add charts) |

---

## Success Metrics

### Adoption Metrics

| Metric | v2.0 Baseline | v3.0 Target (Q3 2026) | v5.0 Target (Q4 2027) |
|--------|--------------|---------------------|---------------------|
| **GitHub Stars** | ~50 | 500 | 2,000 |
| **Docker Pulls** | ~1K | 10K | 100K |
| **Active Installations** | ~20 | 200 | 2,000 |
| **CI Integrations** | 0 | 100 | 1,000 |
| **Community Plugins** | 5 | 25 | 100 |
| **Documentation Page Views** | 500/mo | 5K/mo | 25K/mo |

### Quality Metrics

| Metric | v2.0 | v3.0 Target | v5.0 Target |
|--------|------|------------|------------|
| **False Positive Rate** | ~20% | < 10% | < 5% |
| **Scan Reliability** | ~85% | > 95% | > 99% |
| **Test Coverage** | 60% | > 80% | > 90% |
| **Bug Resolution Time** | 14 days | < 7 days | < 3 days |
| **User Satisfaction (NPS)** | Unknown | 40+ | 60+ |

### Performance Metrics

| Metric | v2.0 | v3.0 Target | v5.0 Target |
|--------|------|------------|------------|
| **Smoke Scan** | < 2 min | < 90s | < 60s |
| **Standard Scan** | < 10 min | < 7 min | < 5 min |
| **Deep Scan** | < 30 min | < 20 min | < 15 min |
| **Fleet (100 sites)** | ~8 hours (serial) | < 2 hours (parallel) | < 30 min (distributed) |
| **Memory Usage** | ~2 GB | < 1.5 GB | < 1 GB |

### Business Metrics (If Monetized)

| Metric | Year 1 (2026) | Year 2 (2027) | Year 3 (2028) |
|--------|--------------|--------------|--------------|
| **Paying Customers** | 10 | 50 | 200 |
| **MRR** | $1K | $10K | $50K |
| **Customer Acquisition Cost** | < $500 | < $200 | < $100 |
| **Customer Lifetime Value** | $2K | $5K | $10K |
| **Churn Rate** | < 5% | < 3% | < 2% |

---

## Risk Mitigation & Dependencies

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **ZAP Proxy Instability** | Medium | High | Add Burp Suite integration fallback; improve retry logic with exponential backoff |
| **Playwright Breaking Changes** | Medium | Medium | Pin Playwright versions; comprehensive E2E test suite; monitor release notes |
| **Bot Detection Evasion Failure** | High | High | Continuously update stealth techniques; User-Agent rotation; residential proxy support |
| **False Positive Overload** | High | Medium | ML-based suppression; user feedback loop; BaselineService enhancement |
| **Scan Performance Degradation** | Medium | High | Distributed worker architecture; horizontal scaling; caching optimizations |
| **Compliance Mapping Errors** | Medium | Critical | Consult with auditors; open-source for community validation; annual reviews |
| **Active Scan Legal Issues** | Low | Critical | Guardrails (ACTIVE_SCAN_ALLOWED + allowlist); prominent warnings; terms of service |

### External Dependencies

| Dependency | License | Criticality | Risk Mitigation |
|------------|---------|-------------|-----------------|
| **Playwright** | Apache 2.0 | Critical | Core to product; no alternatives; pin versions |
| **OWASP ZAP** | Apache 2.0 | High | Add Burp Suite fallback; consider custom proxy |
| **Lighthouse** | Apache 2.0 | High | Google maintains actively; fallback to WebPageTest API |
| **axe-core** | MPL 2.0 | Medium | Consider pa11y as alternative |
| **OpenAI API** | Proprietary | Low | Optional feature; support Claude/local models |

### Open Questions

**Business & Strategy:**
1. Should we build a SaaS offering or remain pure open-source?
2. What's the commercial licensing model? (Dual-license? Support contracts? Enterprise features?)
3. How do we monetize without alienating open-source community?
4. Should we target SMBs or enterprises first?

**Technical Implementation:**
5. Should we support Puppeteer alongside Playwright for compatibility?
6. How do we handle authenticated scans beyond simple login? (OAuth, SAML, MFA)
7. Should pentest modules be opt-in plugins to reduce legal risk?
8. What's the right balance between scan thoroughness and speed?
9. Should workers use Docker for isolation or run natively for performance?
10. How do we prevent scanner resource exhaustion (memory leaks, browser crashes)?

**Compliance & Security:**
11. How do we verify compliance mappings are audit-ready? (Hire consultant?)
12. Should active scanning be disabled by default due to legal implications?
13. What GDPR consent is needed for RUM data collection?
14. How do we handle PII in scan results? (Redaction vs. no collection)
15. Should we get SOC2 certified ourselves to sell to enterprises?

**Community & Ecosystem:**
16. Should we create a plugin marketplace?
17. How do we sandbox untrusted community plugins?
18. What's the governance model for the project? (BDFL? Foundation?)
19. Should we fund security researchers to audit LSCM itself?
20. How do we balance feature requests from OSS users vs. paying customers?

---

## Appendix A: Current Codebase Analysis

### File Structure (v2.0)

```
stealth-compliance-monitor/
├── src/
│   ├── index.ts                    # Entry point, orchestration, CLI arg parsing
│   │
│   ├── config/
│   │   ├── env.ts                  # Environment config from .env
│   │   ├── compliance.config.ts    # Profile definitions (smoke, standard, deep)
│   │   └── index.ts
│   │
│   ├── core/
│   │   ├── ComplianceRunner.ts     # Main scan orchestrator
│   │   ├── UserFlowRunner.ts       # User journey testing
│   │   ├── CustomCheckLoader.ts    # Plugin system for custom checks
│   │   ├── ScannerRegistry.ts      # Manage scanner lifecycle
│   │   └── index.ts
│   │
│   ├── services/
│   │   # Browser & Foundation
│   │   ├── BrowserService.ts       # Playwright wrapper, ZAP proxy, stealth
│   │   ├── AuthService.ts          # Login/authentication
│   │   │
│   │   # Passive Monitors (attached to browser)
│   │   ├── NetworkSpy.ts           # Request/response tracking
│   │   ├── SecretScanner.ts        # API keys, tokens in JS sources
│   │   ├── ConsoleMonitor.ts       # Console errors/warnings
│   │   ├── SupabaseSecurityScanner.ts  # Supabase-specific checks
│   │   ├── FrontendVulnerabilityScanner.ts  # Vulnerable library detection
│   │   │
│   │   # Audit & Scanning
│   │   ├── AuditService.ts         # Orchestrates Lighthouse + ZAP
│   │   ├── LighthouseService.ts    # Performance, A11y, SEO scores
│   │   ├── ZapService.ts           # Passive ZAP alerts
│   │   ├── ZapActiveScanner.ts     # Active ZAP spider + scan
│   │   │
│   │   # Crawling & Discovery
│   │   ├── CrawlerService.ts       # Intelligent page discovery
│   │   ├── DataIntegrityService.ts # Logical data validation
│   │   │
│   │   # Page Validators
│   │   ├── A11yScanner.ts          # axe-core WCAG testing
│   │   ├── SEOValidator.ts         # Meta tags, schema.org
│   │   ├── VisualSentinel.ts       # Visual regression
│   │   ├── AssetValidator.ts       # Image/media validation
│   │   ├── LinkChecker.ts          # Broken link detection
│   │   ├── InteractionTester.ts    # Form/button testing
│   │   ├── ResilienceTester.ts     # Error handling
│   │   │
│   │   # Security (Active Testing)
│   │   ├── SecurityAssessment.ts   # Black-box pentest (IDOR, XSS, SQLi)
│   │   ├── PiiScanner.ts           # PII/DLP detection
│   │   ├── ApiEndpointTester.ts    # REST/GraphQL security
│   │   │
│   │   # Intelligence & Operations
│   │   ├── VulnIntelligenceService.ts  # CVE enrichment, CVSS
│   │   ├── AiRemediationService.ts # GPT-4 code fixes
│   │   ├── HistoryService.ts       # Trend tracking
│   │   ├── BaselineService.ts      # False positive management
│   │   │
│   │   # Reporting & Notifications
│   │   ├── WebhookService.ts       # Slack/Teams/Discord alerts
│   │   ├── SiemLogger.ts           # Splunk/Datadog logs
│   │   ├── PersistenceService.ts   # Write-Ahead Log (WAL)
│   │   ├── ReportGenerator.ts      # Markdown reports
│   │   ├── HtmlReportGenerator.ts  # Interactive dashboard
│   │   ├── FleetReportGenerator.ts # Multi-site summary
│   │   └── index.ts
│   │
│   ├── types/
│   │   └── index.ts                # TypeScript type definitions
│   │
│   ├── utils/
│   │   ├── logger.ts               # Winston logging
│   │   ├── throttle.ts             # Rate limiting
│   │   ├── progress.ts             # Terminal progress bars
│   │   ├── random.ts               # Deterministic randomness
│   │   ├── redaction.ts            # PII redaction
│   │   ├── retry.ts                # Retry logic
│   │   └── index.ts
│   │
│   └── data/
│       └── compliance-map.ts       # Vulnerability→CWE mappings
│
├── custom_checks/                  # User-provided custom checks
├── plugins/                        # Community plugins
│   ├── examples/
│   └── community/
│
├── reports/                        # Generated reports
│   ├── latest.json
│   ├── {domain}-audit-report.html
│   └── fleet-dashboard.html
│
├── screenshots/                    # Failure screenshots
├── snapshots/                      # Visual regression baselines
├── logs/                           # Application logs
│
├── tests/                          # Jest + Playwright tests
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── .env                            # Configuration
├── .env.example                    # Configuration template
├── docker-compose.yml              # ZAP proxy orchestration
├── Dockerfile                      # Container image
├── package.json                    # Dependencies
├── tsconfig.json                   # TypeScript config
├── playwright.config.ts            # Playwright settings
├── jest.config.js                  # Jest config
│
├── ARCHITECTURE.md                 # System architecture docs
├── README.md                       # User documentation
├── CONTRIBUTING.md                 # Contribution guidelines
├── SECURITY.md                     # Security policy
└── LICENSE                         # MIT License
```

### Technology Stack

**Runtime & Language:**
- Node.js 20+
- TypeScript 5.7

**Browser Automation:**
- Playwright 1.40 (Chromium headless)
- Chrome Launcher

**Security Tools:**
- OWASP ZAP (Docker container)
- axe-core (accessibility)

**Performance:**
- Lighthouse 12.4
- Core Web Vitals

**Utilities:**
- Winston (logging)
- dotenv (config)
- chalk (terminal colors)
- p-limit (concurrency)
- pixelmatch + pngjs (visual regression)

**Testing:**
- Jest (unit tests)
- @playwright/test (E2E tests)

**CI/CD:**
- GitHub Actions

---

## Appendix B: Migration from Initial PRD

### What Was Wrong with v1.0 PRD?

The initial PRD (now saved as [Stealth-Compliance-Monitor-PRD-OLD.md](Stealth-Compliance-Monitor-PRD-OLD.md)) described a **completely different product**:

**Initial PRD Fantasy (WRONG):**
- ❌ CLI tool for scanning **source code repositories**
- ❌ Docker-based scanners (Semgrep for SAST, Gitleaks for secrets, Trivy for containers)
- ❌ GitHub Actions integration for **CI/CD repo scanning**
- ❌ Hub-and-spoke orchestrator spawning Docker containers
- ❌ TimescaleDB for storing scan results
- ❌ Config file: `.stealth-monitor.yml`
- ❌ Scanner adapters: `SemgrepAdapter`, `GitleaksAdapter`, `TrivyAdapter`

**Actual Product (CORRECT):**
- ✅ Browser-based tool for scanning **live websites**
- ✅ Playwright + OWASP ZAP for **dynamic testing**
- ✅ No GitHub Actions integration (yet - proposed in v3.0)
- ✅ Single-process orchestrator (ComplianceRunner)
- ✅ JSON file storage (no database)
- ✅ Config file: `.env`
- ✅ Services: `BrowserService`, `LighthouseService`, `ZapService`, etc.

### Why the Confusion?

The initial PRD was written **without reviewing the actual codebase**. It assumed the product was similar to tools like Snyk, GitHub Advanced Security, or Semgrep Cloud (static code analysis), when in fact it's more like:
- **Synthetic monitoring** (Datadog Synthetics, Pingdom)
- **DAST tools** (Burp Suite, Acunetix)
- **Lighthouse CI**
- **Accessibility testing** (pa11y, axe DevTools)

All combined into one platform.

### Key Lessons

1. **Always review actual code before writing specs** (ARCHITECTURE.md, README.md, source files)
2. **Product names can be misleading** ("Compliance Monitor" sounds like code scanning, but it's actually website scanning)
3. **Ask clarifying questions early** (What does this tool scan? Repos or URLs?)

---

*Document refactored: January 2026*
*Based on actual codebase analysis: [ARCHITECTURE.md](ARCHITECTURE.md), [README.md](README.md), [src/](src/)*
