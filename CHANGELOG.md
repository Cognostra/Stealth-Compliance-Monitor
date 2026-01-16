# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

---

## [1.0.0] - 2026-01-16

### 🎉 Initial Release

This is the first stable release of Stealth Compliance Monitor, an enterprise-grade web compliance and security auditing platform.

### Added

#### Core Scanning Engine
- **BrowserService** - Playwright-based headless browser automation with stealth mode
- **ScannerRegistry** - Modular plugin architecture for extensible scanning
- **ComplianceRunner** - Orchestrates multi-phase compliance audits
- **UserFlowRunner** - Executes custom user journey scripts

#### Security Scanning
- **ZapService** - OWASP ZAP proxy integration for passive vulnerability detection
- **ZapActiveScanner** - Active security scanning with configurable attack policies
- **SecretScanner** - Detects leaked API keys, tokens, and credentials in JavaScript
- **PiiScanner** - Identifies exposed PII (SSN, credit cards, phone numbers)
- **SupabaseSecurityScanner** - Supabase-specific security checks (RLS, service_role keys)
- **FrontendVulnerabilityScanner** - Detects vulnerable JavaScript libraries with CVE data
- **SecurityAssessment** - Black-box pentesting (IDOR, XSS, SQLi, auth bypass probes)

#### Performance & Accessibility
- **LighthouseService** - Google Lighthouse integration for performance audits
- **A11yScanner** - axe-core integration for WCAG 2.1 AA compliance
- **AssetValidator** - Broken image detection, oversized resources, 404 errors

#### Visual Regression
- **VisualSentinel** - Pixel-level screenshot comparison with configurable thresholds
- **BaselineService** - Manages visual regression baselines

#### Network & Monitoring
- **NetworkSpy** - Captures and analyzes all network traffic
- **ConsoleMonitor** - Captures browser console errors and warnings
- **LinkChecker** - Validates internal and external links

#### Reporting & Integration
- **HtmlReportGenerator** - Interactive HTML dashboard with filtering
- **FleetReportGenerator** - Multi-site fleet compliance dashboards
- **HistoryService** - Historical trend tracking and analysis
- **AiRemediationService** - OpenAI-powered code fix suggestions
- **WebhookService** - Slack, Teams, Discord notifications with HMAC signatures
- **SiemLogger** - ECS/OCSF formatted logs for Splunk, Datadog, Elastic

#### Enterprise Features
- **Custom Compliance Checks** - Plugin system for custom rules
- **API Endpoint Testing** - REST/GraphQL security testing
- **Fleet Mode** - Scan multiple sites with aggregated reporting
- **Scan Profiles** - Quick, standard, deep, and stealth scan modes
- **Debug Mode** - Verbose logging for troubleshooting

#### Infrastructure
- **Docker Support** - Full Docker Compose setup with ZAP proxy
- **GitHub Actions** - CI/CD workflows for testing and scheduled scans
- **Write-Ahead Logging** - Crash resilience with partial recovery

### Security
- HMAC-SHA256 webhook signatures
- Secret redaction in logs
- Bot detection bypass (stealth mode)
- Configurable rate limiting

### Documentation
- Comprehensive README with examples
- Architecture documentation
- Custom check development guide
- API endpoint testing guide

---

## [0.9.0] - 2026-01-10

### Added
- Fleet mode for multi-site scanning
- FleetReportGenerator with summary statistics
- Trend analysis in HistoryService
- CSV export for historical data

### Changed
- Improved WebhookService with retry logic
- Enhanced SiemLogger with ECS format compliance

### Fixed
- Memory leak in long-running scans
- Race condition in parallel scanner execution

---

## [0.8.0] - 2026-01-05

### Added
- AI Remediation Service with OpenAI integration
- Batch fix generation for multiple issues
- Remediation templates for common vulnerabilities
- Token usage tracking

### Changed
- Upgraded to Playwright 1.40
- Improved error handling in BrowserService

### Fixed
- Screenshot capture timing issues
- Report generation with special characters

---

## [0.7.0] - 2025-12-20

### Added
- ZAP Active Scanner integration
- Configurable scan policies
- Attack strength and threshold settings
- Progress tracking for active scans

### Changed
- Refactored ZapService for better modularity
- Improved vulnerability severity mapping

### Fixed
- ZAP API timeout handling
- Duplicate alert filtering

---

## [0.6.0] - 2025-12-10

### Added
- SIEM Logger with multiple output formats
- Splunk HEC integration
- Datadog webhook support
- Event buffering and batch logging

### Changed
- Standardized security event format
- Improved log rotation

---

## [0.5.0] - 2025-12-01

### Added
- Webhook notifications (Slack, Teams, Discord)
- Custom webhook support with HMAC signatures
- Alert filtering by severity
- Platform-specific message formatting

### Changed
- Refactored notification system
- Added exponential backoff for retries

---

## [0.4.0] - 2025-11-20

### Added
- Visual regression testing with VisualSentinel
- Baseline management service
- Configurable diff thresholds
- Diff image generation

### Changed
- Screenshot naming convention
- Storage optimization for baselines

---

## [0.3.0] - 2025-11-10

### Added
- Custom compliance check system
- Plugin loader with validation
- Example checks (header validation, meta tags)
- Plugin development documentation

### Changed
- Modular scanner architecture
- Improved type definitions

---

## [0.2.0] - 2025-11-01

### Added
- Lighthouse integration for performance audits
- Core Web Vitals tracking
- axe-core accessibility scanning
- HTML report generation

### Changed
- Improved browser automation
- Better error recovery

---

## [0.1.0] - 2025-10-15

### Added
- Initial project setup
- Basic browser automation with Playwright
- ZAP proxy integration (passive mode)
- Secret detection scanner
- Network traffic monitoring
- Console error capture
- Basic CLI interface

---

[Unreleased]: https://github.com/Cognostra/Stealth-Compliance-Monitor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v1.0.0
[0.9.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.9.0
[0.8.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.8.0
[0.7.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.7.0
[0.6.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.6.0
[0.5.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.5.0
[0.4.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.4.0
[0.3.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.3.0
[0.2.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.2.0
[0.1.0]: https://github.com/Cognostra/Stealth-Compliance-Monitor/releases/tag/v0.1.0
