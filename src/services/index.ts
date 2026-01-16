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

export { ReportGenerator } from './ReportGenerator.js';
export type { ReportData } from './ReportGenerator.js';

export { DataIntegrityService } from './DataIntegrityService.js';
export type { IntegrityTestResult, IntegritySessionResult } from './DataIntegrityService.js';

export { VisualSentinel } from './VisualSentinel.js';
export type { VisualTestResult } from './VisualSentinel.js';

export { NetworkSpy } from './NetworkSpy.js';
export type { NetworkIncident } from './NetworkSpy.js';

export { SecretScanner } from './SecretScanner.js';
export type { LeakedSecret } from './SecretScanner.js';

export { AssetValidator } from './AssetValidator.js';
export type { AssetCheckResult } from './AssetValidator.js';

export { ConsoleMonitor } from './ConsoleMonitor.js';
export type { ConsoleError } from './ConsoleMonitor.js';

export { LinkChecker } from './LinkChecker.js';
export type { LinkCheckResult, ValidatedLink } from './LinkChecker.js';

export { SEOValidator } from './SEOValidator.js';
export type { SEOResult } from './SEOValidator.js';

export { InteractionTester } from './InteractionTester.js';
export type { InteractionTestResult } from './InteractionTester.js';

export { ResilienceTester } from './ResilienceTester.js';
export type { ResilienceCheckResult } from './ResilienceTester.js';

export { A11yScanner } from './A11yScanner.js';
export type { A11yResult, A11yViolation } from './A11yScanner.js';

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
