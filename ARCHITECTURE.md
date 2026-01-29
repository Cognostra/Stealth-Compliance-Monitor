# 🛡️ Stealth Compliance Monitor - Architecture Map (v3.0)

## Overview

The **Live-Site Compliance Monitor (LSCM)** is a comprehensive automated testing suite that performs passive security scanning, performance auditing, accessibility testing, and black-box penetration testing on live web applications. Version 3.0 introduces a modular architecture with Policy-as-Code, modular compliance frameworks, and distributed fleet scanning.

---

## 📊 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    ENTRY POINT                                       │
│                                   src/index.ts                                       │
│                              (Orchestration Layer)                                   │
└────────────┬────────────────────────────┬───────────────────────────────┬───────────┘
             │                            │                               │
             ▼                            ▼                               ▼
┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
│       CLI LAYER         │    │      CORE RUNNERS       │    │      V3 PROCESSOR       │
│    src/config/cli.ts    │    │      src/core/          │    │    src/v3/processor.ts  │
└─────────────────────────┘    └─────────────────────────┘    └─────────────────────────┘
             │                            │                               │
             ▼                            ▼                               ▼
┌─────────────────────┐        ┌─────────────────────────┐        ┌─────────────────────┐
│    CONFIG LAYER     │        │        SERVICES         │        │     V3 FEATURES     │
│    src/config/      │        │      src/services/      │        │      src/v3/        │
├─────────────────────┤        ├─────────────────────────┤        ├─────────────────────┤
│ • env.ts            │        │ • ComplianceRunner      │        │ • PolicyEngine      │
│ • compliance.config │        │ • BrowserService        │        │ • SarifReporter     │
│ • cli.ts            │        │ • ZapService            │        │ • ComplianceMap     │
└─────────────────────┘        │ • LighthouseService     │        │ • ExecutiveReporter │
                               └─────────────────────────┘        └─────────────────────┘
```

---

## 🔧 Execution Flow (v3.0)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 0: Initialization                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │  CLI & Config Loading                                                        │    │
│  │  ├── Parse CLI args (cli.ts)                                                 │    │
│  │  ├── Load Env & Profile (compliance.config.ts)                               │    │
│  │  └── Initialize CronScheduler (if daemon mode)                               │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Fleet Execution (Parallel)                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │  For each Target (p-limit concurrency):                                      │    │
│  │  ├── Instantiate ComplianceRunner                                            │    │
│  │  ├── BrowserService.initialize() (Stealth Mode)                              │    │
│  │  ├── AuthService.login()                                                     │    │
│  │  ├── AuditService.runFullAudit() (Lighthouse + ZAP)                          │    │
│  │  ├── CrawlerService.discover()                                               │    │
│  │  ├── SecurityAssessment.assess() (Active/Passive)                            │    │
│  │  └── TrendService.record()                                                   │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Aggregration & Standard Reporting                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │  FleetReportGenerator                                                        │    │
│  │  ├── Aggregate all site results                                              │    │
│  │  ├── Generate Fleet Dashboard (HTML)                                         │    │
│  │  └── Generate fleet-summary.json                                             │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: V3 Advanced Processing (src/v3/processor.ts)                                 │
│  ┌──────────────────────────────────────────────────────────────────────────────┐    │
│  │  Post-Processing Features                                                    │    │
│  │  ├── PolicyEngine: Evaluate Pass/Fail rules from .compliance-policy.yml      │    │
│  │  ├── SarifReporter: Convert findings to SARIF for GitHub Code Scanning       │    │
│  │  ├── ComplianceService: Map findings to SOC2/GDPR/HIPAA controls             │    │
│  │  └── ExecutiveReporter: Generate PDF Executive Summary                       │    │
│  └──────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Services Dependency Map

```
                              ┌─────────────────┐
                              │  BrowserService │
                              │  (Core Engine)  │
                              └────────┬────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌─────────────────┐            ┌─────────────────┐
│   Spies &     │            │    Auth &       │            │    Testing      │
│   Monitors    │            │    Crawling     │            │    Services     │
├───────────────┤            ├─────────────────┤            ├─────────────────┤
│ NetworkSpy    │            │ AuthService     │            │ AuditService    │
│ SecretScanner │            │ CrawlerService  │◄──────────►│ LighthouseServ  │
│ PiiScanner    │            │ DataIntegrity   │            │ ZapService      │
│ SupabaseScan  │            │                 │            │ AiRemediation   │
│ VulnScanner   │            │                 │            │ BaselineService │
└───────────────┘            └─────────────────┘            └─────────────────┘
                                       │
                                       │ Uses
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌─────────────────┐            ┌─────────────────┐
│   Page        │            │    Content      │            │    Security     │
│   Validators  │            │    Checkers     │            │    Assessment   │
├───────────────┤            ├─────────────────┤            ├─────────────────┤
│ A11yScanner   │            │ AssetValidator  │            │ SecurityAssess  │
│ SEOValidator  │            │ LinkChecker     │            │   (Pentest)     │
│ VisualSentinel│            │ ResilienceTest  │            │                 │
│ InteractTest  │            │                 │            │                 │
└───────────────┘            └─────────────────┘            └─────────────────┘
                                       │
                                       ▼
                            ┌─────────────────┐
                            │    Report       │
                            │    Generators   │
                            ├─────────────────┤
                            │ ReportGenerator │
                            │ HtmlReportGen   │
                            └─────────────────┘
```

---

## 📁 Directory Structure (v3.0)

```
stealth-compliance-monitor/
├── src/
│   ├── index.ts                    # Main entry point (orchestrator)
│   ├── config/                     # Configuration & CLI parsing
│   │   ├── cli.ts                  # CLI argument parser (NEW)
│   │   ├── env.ts                  # Environment validation
│   │   └── compliance.config.ts    # Profile definitions
│   │
│   ├── core/                       # Core Logic
│   │   ├── ComplianceRunner.ts     # Per-site runner
│   │   └── index.ts
│   │
│   ├── services/                   # Standard Services (v2)
│   │   ├── BrowserService.ts       # Playwright wrapper
│   │   ├── ZapService.ts           # OWASP ZAP integration
│   │   ├── LighthouseService.ts    # Performance/A11y
│   │   ├── WebhookService.ts       # Notifications
│   │   └── ... (See README)
│   │
│   ├── v3/                         # V3 Advanced Features (NEW)
│   │   ├── processor.ts            # V3 Logic Orchestrator
│   │   ├── core/
│   │   │   └── PolicyEngine.ts     # Logic for custom policies
│   │   ├── compliance/
│   │   │   └── frameworks.ts       # SOC2/GDPR mappings
│   │   ├── reporters/
│   │   │   └── SarifReporter.ts    # SARIF generation
│   │   ├── scheduler/
│   │   │   └── CronScheduler.ts    # Continuous monitoring
│   │   └── services/
│   │       └── TrendService.ts     # Historical analysis
│   │   └── utils/                  # V3-specific utilities
│   │       ├── constants.ts        # Centralized magic numbers and limits
│   │       ├── crypto.ts           # Secure hashing and key utilities
│   │       └── validation.ts       # Path & input validators (POLICY_ALLOWED_DIRS)
│   │
│   ├── types/                      # TypeScript definitions
│   └── utils/                      # Shared utilities
│
├── reports/                        # Output artifacts
├── screenshots/                    # Failure captures
├── snapshots/                      # Visual regression baselines
└── custom_checks/                  # User plugins
```

---

## 🔌 External Dependencies

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL INTEGRATIONS                                   │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│   Playwright    │           │   OWASP ZAP     │           │   Lighthouse    │
│   (Browser)     │           │   (Security)    │           │   (Performance) │
├─────────────────┤           ├─────────────────┤           ├─────────────────┤
│ • Chromium      │           │ • Passive proxy │           │ • Core Web      │
│ • Page control  │           │ • Alert API     │           │   Vitals        │
│ • Network       │           │ • No active     │           │ • A11y scores   │
│   interception  │           │   scanning!     │           │ • SEO scores    │
│ • Screenshots   │           │                 │           │ • Best Practice │
└─────────────────┘           └─────────────────┘           └─────────────────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      │
                                      ▼
                        ┌─────────────────────────┐
                        │     axe-core            │
                        │     (Accessibility)     │
                        ├─────────────────────────┤
                        │ • WCAG 2.1 violations   │
                        │ • Impact severity       │
                        │ • Element targeting     │
                        └─────────────────────────┘
```

---

## 🛡️ V3 Features & Integrations

| Feature | Component | Description |
|---------|-----------|-------------|
| **Policy-as-Code** | `PolicyEngine` | Evaluates YAML-based pass/fail criteria (e.g., "No Criticals", "LCP < 2.5s") |
| **SARIF Export** | `SarifReporter` | Standardized format for GitHub Advanced Security integration |
| **Compliance Mapping** | `ComplianceService` | Maps technical findings to regulatory controls (SOC2 CC6.1, GDPR Art32) |
| **Executive PDF** | `ExecutiveReporter` | One-page high-level summary for leadership |
| **Continuous Monitoring** | `CronScheduler` | Built-in daemon for scheduled audits |
| **Visual Regression** | `VisualSentinel` | Pixel-perfect layout change detection |
| **Security Hardening** | `v3/utils/constants.ts` + `validation.ts` | Centralized constants, file-size and path validation, and stricter YAML parsing limits (22 issues addressed) |
| **Circuit Breaker & Cleanup** | `CronScheduler` + `TrendService` | Circuit breaker for scheduled scans and TrendService.cleanupOldRecords to limit memory growth |

---

## 📈 Output Report Structure

### JSON Report (`latest.json`)

```json
{
  "meta": { "version", "generatedAt", "targetUrl", "duration" },
  "authentication": { "success", "duration" },
  "crawl": { "pagesVisited", "failedPages", "pageResults[]" },
  "integrity": { "testsRun", "passed", "failed" },
  "network_incidents": [],
  "leaked_secrets": [],
  "supabase_issues": [],
  "vulnerable_libraries": [],
  "security_assessment": {
    "findings": [],
    "summary": { "critical", "high", "medium", "low" },
    "reconnaissance": { "endpoints", "techStack", "authMechanism" }
  },
  "lighthouse": { "scores", "metrics" },
  "security_alerts": [],
  "summary": { "scores", "passedAudit" }
}
```

### HTML Dashboard Features

- 🎯 Health Score Gauge (0-100)
- 📊 Score Cards (Performance, Accessibility, SEO, Security)
- ⚡ Quick Wins (High impact, low effort fixes)
- 🔒 Security Assessment Summary
- 📋 Remediation Grid (Sortable, filterable)
- 📈 Historical Trend Charts (Results over time)
- 🤖 AI-Suggested Code Fixes
- 📄 PDF Export Support
- 🔍 Playwright Locators (Copy-to-clipboard)

---

## 📊 Data Flow (v3.0)

1. **Input**: `.env`, CLI Args, `.compliance-policy.yml`
2. **Collection**: Distributed Scan of N Targets
3. **Normalization**: `FleetReportGenerator` normalizes checking results
4. **V3 Processing**:
   - **Policy**: `AuditResult` -> `Pass/Fail`
   - **Compliance**: `Findings` -> `Control Mappings`
   - **SARIF**: `Findings` -> `sarif.json`
5. **Output**: HTML Dashboards, JSON Logs, SARIF, PDF, Webhooks

---

## 🚀 Usage

```bash
# Run full compliance audit
npx ts-node src/index.ts

# With Docker (includes ZAP proxy)
docker-compose up

# View reports
open reports/latest.json
open reports/loadout-audit-report.html
```

---

*Last Updated: January 2026 (v3.0 Release)*
