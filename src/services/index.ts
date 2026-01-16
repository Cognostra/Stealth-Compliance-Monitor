/**
 * Services Index
 * Export all services
 */

export { BrowserService } from './BrowserService.js';
export type { NavigationResult, InteractionResult, ScreenshotResult } from './BrowserService.js';

export { AuthService, AuthenticationError } from './AuthService.js';
export type { LoginSelectors, AuthResult } from './AuthService.js';

export { AuditService } from './AuditService.js';
export type {
    LighthouseScores,
    LighthouseResult,
    SecurityAlert,
    SecurityAlertsByRisk,
    AuditResult
} from './AuditService.js';

export { CrawlerService } from './CrawlerService.js';
export type { PageCrawlResult, CrawlSessionResult } from './CrawlerService.js';

export { LighthouseService } from './LighthouseService.js';

export { ZapService } from './ZapService.js';

export { ReportGenerator, ReportData } from './ReportGenerator.js';

export { DataIntegrityService, IntegrityTestResult, IntegritySessionResult } from './DataIntegrityService.js';

export { VisualSentinel, VisualTestResult } from './VisualSentinel.js';

export { NetworkSpy, NetworkIncident } from './NetworkSpy.js';

export { SecretScanner, LeakedSecret } from './SecretScanner.js';

export { AssetValidator, AssetCheckResult } from './AssetValidator.js';

export { ConsoleMonitor, ConsoleError } from './ConsoleMonitor.js';

export { LinkChecker, LinkCheckResult, ValidatedLink } from './LinkChecker.js';

export { SEOValidator, SEOResult } from './SEOValidator.js';

export { InteractionTester, InteractionTestResult } from './InteractionTester.js';

export { ResilienceTester, ResilienceCheckResult } from './ResilienceTester.js';

export { A11yScanner, A11yResult, A11yViolation } from './A11yScanner.js';

export { PersistenceService, persistenceService } from './PersistenceService.js';
export type { WALEntry, LogEntryType, HydratedSession, SessionMetadata } from './PersistenceService.js';

export { HtmlReportGenerator } from './HtmlReportGenerator.js';
export type { BrandingConfig } from './HtmlReportGenerator.js';

export { ZapActiveScanner } from './ZapActiveScanner.js';
export type { ActiveScanResult, ActiveScanProgress, SpiderProgress } from './ZapActiveScanner.js';

export { ApiEndpointTester } from './ApiEndpointTester.js';
export type { ApiEndpoint, ApiFinding, ApiTestResult } from './ApiEndpointTester.js';

export { VulnIntelligenceService } from './VulnIntelligenceService.js';
export type {
    CvssScore,
    CweInfo,
    ExploitInfo,
    RemediationInfo,
    EnrichedVulnerability,
    VulnIntelligenceConfig,
    IntelligenceSummary,
} from './VulnIntelligenceService.js';

export { HistoryService } from './HistoryService.js';
export type { RunSummary, TrendAnalysis, ComparisonResult } from './HistoryService.js';

export { SiemLogger } from './SiemLogger.js';
export type { SecurityIssue, EcsEvent, EventBatch } from './SiemLogger.js';

export { WebhookService } from './WebhookService.js';
export type { WebhookPayload, WebhookResult } from './WebhookService.js';

export { AiRemediationService } from './AiRemediationService.js';
export type { RemediationRequest, RemediationResponse, BatchRemediationResult } from './AiRemediationService.js';

export { FleetReportGenerator } from './FleetReportGenerator.js';
export type { FleetSiteResult, FleetSummary } from './FleetReportGenerator.js';
