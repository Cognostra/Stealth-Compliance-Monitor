# Stealth Compliance Monitor - Architecture Map (v3.2)

## Overview

The **Live-Site Compliance Monitor (LSCM)** is a comprehensive automated testing suite that performs passive security scanning, performance auditing, accessibility testing, and black-box penetration testing on live web applications. Version 3.0 introduced a modular architecture with Policy-as-Code, modular compliance frameworks, and distributed fleet scanning. Version 3.1 added Electron app auditing, Flutter web semantics scanning, local LLM remediation, fintech compliance profiles, and a Python plugin bridge. **Version 3.2** introduces 30+ new enterprise-grade features across 6 tiers: Advanced Security, AI-Powered Analysis, Web Platform Security, Infrastructure/DevSecOps, Enterprise Compliance, and Developer Integrations.

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
│ • cli.ts            │        │ • ElectronBrowserSvc    │        │ • ComplianceMap     │
└─────────────────────┘        │ • ZapService            │        │ • ExecutiveReporter │
                               │ • LighthouseService     │        │ • ScannerRegistry   │
                               │ • OllamaService         │        └─────────────────────┘
                               │ • FintechScanner        │
                               │ • FlutterSemanticsScnr  │
                               │ • SbomScanner           │
                               │ • GraphQLDeepScanner    │
                               │ • WebSocketAuditor      │
                               │ • CspViolationCollector │
                               │ • FingerprintDetector   │
                               │ • VisualAiCompliance    │
                               │ • WebRTCAnalyzer        │
                               │ • PwaSecurityScanner    │
                               │ • FairRiskQuantifier    │
                               └─────────────────────────┘
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
│ FintechScnr   │            │                 │            │ OllamaService   │
│ FlutterSemScn │            │                 │            │                 │
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

## Directory Structure (v3.1)

```
stealth-compliance-monitor/
├── src/
│   ├── index.ts                    # Main entry point (orchestrator)
│   ├── config/                     # Configuration & CLI parsing
│   │   ├── cli.ts                  # CLI argument parser
│   │   ├── env.ts                  # Environment validation
│   │   └── compliance.config.ts    # Profile definitions (smoke/standard/deep/fintech)
│   │
│   ├── core/                       # Core Logic
│   │   ├── ComplianceRunner.ts     # Per-site runner
│   │   ├── ScannerRegistry.ts      # IScanner registration & result map
│   │   ├── CustomCheckLoader.ts    # TS/JS/Python plugin loader
│   │   ├── PythonCheckRunner.ts    # Python subprocess bridge (v3.1)
│   │   └── index.ts
│   │
│   ├── services/                   # Services
│   │   ├── BrowserService.ts       # Playwright wrapper (web targets)
│   │   ├── ElectronBrowserService.ts # Electron app launcher (v3.1)
│   │   ├── FintechScanner.ts       # Crypto-jacking/PCI-DSS/wallet drainer (v3.1)
│   │   ├── FlutterSemanticsScanner.ts # Flutter web a11y (v3.1)
│   │   ├── OllamaService.ts       # Local LLM remediation (v3.1)
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
    ├── *.ts / *.js                 # TypeScript/JavaScript checks
    └── python/                     # Python check scripts (v3.1)
        └── example_header_check.py # Example Python plugin
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

## V3 Features & Integrations

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

### V3.1 Features

| Feature | Component | Description |
|---------|-----------|-------------|
| **Electron Auditing** | `ElectronBrowserService` | Audit Electron desktop apps via `electron.launch()` for nodeIntegration, contextIsolation, remote module, CSP, IPC |
| **Flutter Semantics** | `FlutterSemanticsScanner` | Accessibility auditing for Flutter web builds' semantics tree (ARIA, focus, live regions) |
| **Local LLM Remediation** | `OllamaService` | Post-scan AI remediation via local Ollama instance (codellama, deepseek-coder, etc.) |
| **Fintech Profile** | `FintechScanner` | Crypto-jacking detection, PCI-DSS validation, wallet drainer identification |
| **Python Plugin Bridge** | `PythonCheckRunner` + `CustomCheckLoader` | Out-of-process Python check scripts with JSON stdin/stdout contract |

### V3.2 Features (30 New Enterprise Capabilities)

| Tier | Feature | Component | Description |
|------|---------|-----------|-------------|
| **T1: Security** | **SBOM Generator** | `SbomScanner` | Detects npm packages from runtime JS, queries OSV for CVEs |
| **T1: Security** | **GraphQL Deep Scanner** | `GraphQLDeepScanner` | Introspection, depth testing, batch queries, field enumeration |
| **T1: Security** | **WebSocket Auditor** | `WebSocketAuditor` | Plaintext auth detection, sensitive data in frames, rate limiting |
| **T1: Security** | **CSP Violation Collector** | `CspViolationCollector` | Real-time CSP header analysis and violation event collection |
| **T2: AI-Powered** | **Visual AI Compliance** | `VisualAiCompliance` | WCAG color contrast, alt text, brand color validation |
| **T2: AI-Powered** | **Fingerprint Detection** | `FingerprintDetector` | Canvas, WebGL, AudioContext, battery API fingerprinting detection |
| **T2: AI-Powered** | **AI Test Flows** | `AiTestFlowGenerator` | LLM-powered test generation from DOM structure |
| **T2: AI-Powered** | **False Positive Filter** | `FalsePositiveFilter` | Smart deduplication, correlation boosting, confidence scoring |
| **T2: AI-Powered** | **Privacy Policy Analyzer** | `PrivacyPolicyAnalyzer` | GDPR Article 13/14, CCPA compliance vs actual cookie usage |
| **T3: Web Platform** | **WebRTC Analyzer** | `WebRTCAnalyzer` | IP leak detection, TURN server security, data channel analysis |
| **T3: Web Platform** | **PWA Security** | `PwaSecurityScanner` | Service worker analysis, manifest.json security, storage inspection |
| **T3: Web Platform** | **Extension Audit** | `ExtensionAuditScanner` | Browser extension injection and messaging vulnerabilities |
| **T3: Web Platform** | **Mobile Security** | `MobileSecurityScanner` | Device orientation, touch gesture, viewport security analysis |
| **T3: Web Platform** | **Shadow DOM Scanner** | `ShadowDomScanner` | Web Components accessibility and security assessment |
| **T4: Infrastructure** | **WASM Security** | `WasmSecurityScanner` | WebAssembly memory safety and unsafe operation detection |
| **T4: Infrastructure** | **Container Scanner** | `ContainerScannerService` | Dockerfile and docker-compose security auditing |
| **T4: Infrastructure** | **K8s Security** | `K8sSecurityService` | Kubernetes manifest security misconfiguration detection |
| **T4: Infrastructure** | **API Contract Testing** | `ApiContractTester` | OpenAPI/Swagger specification validation |
| **T4: Infrastructure** | **Chaos Engineering** | `ChaosEngineeringService` | Fault injection for resilience testing |
| **T4: Infrastructure** | **Multi-Region** | `MultiRegionComplianceService` | Geographic compliance testing across regions |
| **T5: Enterprise** | **FAIR Risk** | `FairRiskQuantifier` | Factor Analysis of Information Risk quantification |
| **T5: Enterprise** | **Drift Detection** | `ComplianceDriftDetector` | Configuration drift detection over time |
| **T5: Enterprise** | **Third-Party Risk** | `ThirdPartyRiskAggregator` | SecurityScorecard/BitSight integration |
| **T5: Enterprise** | **Real-Time Dashboard** | `RealTimeDashboardService` | Live security monitoring with WebSocket updates |
| **T5: Enterprise** | **Evidence Vault** | `EvidenceVaultService` | Tamper-proof evidence storage for legal hold |
| **T6: Integrations** | **VS Code Extension** | `VsCodeIntegrationService` | IDE integration for instant compliance feedback |
| **T6: Integrations** | **GitHub App** | `GitHubIntegrationService` | PR comments, checks API, repository scanning |
| **T6: Integrations** | **Postman/Newman** | `PostmanIntegrationService` | Collection import and CI/CD pipeline integration |
| **T6: Integrations** | **JIRA/ServiceNow** | `TicketingIntegrationService` | Automated ticket creation for security findings |
| **T6: Integrations** | **Slack/Teams** | `MessagingIntegrationService` | Real-time alerts and notification routing |

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

*Last Updated: January 2026 (v3.2 Release)*
