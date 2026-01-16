/**
 * Services Index
 * Export all services
 */

export { BrowserService } from './BrowserService';
export type { NavigationResult, InteractionResult, ScreenshotResult } from './BrowserService';

export { AuthService, AuthenticationError } from './AuthService';
export type { LoginSelectors, AuthResult } from './AuthService';

export { AuditService } from './AuditService';
export type {
    LighthouseScores,
    LighthouseResult,
    SecurityAlert,
    SecurityAlertsByRisk,
    AuditResult
} from './AuditService';

export { CrawlerService } from './CrawlerService';
export type { PageCrawlResult, CrawlSessionResult } from './CrawlerService';

export { LighthouseService } from './LighthouseService';

export { ZapService } from './ZapService';

export { ReportGenerator, ReportData } from './ReportGenerator';

export { DataIntegrityService, IntegrityTestResult, IntegritySessionResult } from './DataIntegrityService';

export { VisualSentinel, VisualTestResult } from './VisualSentinel';

export { NetworkSpy, NetworkIncident } from './NetworkSpy';

export { SecretScanner, LeakedSecret } from './SecretScanner';

export { AssetValidator, AssetCheckResult } from './AssetValidator';

export { ConsoleMonitor, ConsoleError } from './ConsoleMonitor';

export { LinkChecker, LinkCheckResult, ValidatedLink } from './LinkChecker';

export { SEOValidator, SEOResult } from './SEOValidator';

export { InteractionTester, InteractionTestResult } from './InteractionTester';

export { ResilienceTester, ResilienceCheckResult } from './ResilienceTester';

export { A11yScanner, A11yResult, A11yViolation } from './A11yScanner';

export { PersistenceService, persistenceService } from './PersistenceService';
export type { WALEntry, LogEntryType, HydratedSession, SessionMetadata } from './PersistenceService';

export { HtmlReportGenerator } from './HtmlReportGenerator';
export type { BrandingConfig } from './HtmlReportGenerator';

export { ZapActiveScanner } from './ZapActiveScanner';
export type { ActiveScanResult, ActiveScanProgress, SpiderProgress } from './ZapActiveScanner';

export { ApiEndpointTester } from './ApiEndpointTester';
export type { ApiEndpoint, ApiFinding, ApiTestResult } from './ApiEndpointTester';

export { VulnIntelligenceService } from './VulnIntelligenceService';
export type {
    CvssScore,
    CweInfo,
    ExploitInfo,
    RemediationInfo,
    EnrichedVulnerability,
    VulnIntelligenceConfig,
    IntelligenceSummary,
} from './VulnIntelligenceService';

export { HistoryService } from './HistoryService';
export type { RunSummary, TrendAnalysis, ComparisonResult } from './HistoryService';

export { SiemLogger } from './SiemLogger';
export type { SecurityIssue, EcsEvent, EventBatch } from './SiemLogger';

export { WebhookService } from './WebhookService';
export type { WebhookPayload, WebhookResult } from './WebhookService';

export { AiRemediationService } from './AiRemediationService';
export type { RemediationRequest, RemediationResponse, BatchRemediationResult } from './AiRemediationService';

export { FleetReportGenerator } from './FleetReportGenerator';
export type { FleetSiteResult, FleetSummary } from './FleetReportGenerator';
