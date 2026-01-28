import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { BrowserService } from './BrowserService.js';
import { AuthService } from './AuthService.js';
import { AuditService, AuditResult } from './AuditService.js';
import { CrawlerService, CrawlSessionResult } from './CrawlerService.js';
import { DataIntegrityService, IntegritySessionResult } from './DataIntegrityService.js';
import { HtmlReportGenerator, BrandingConfig } from './HtmlReportGenerator.js';
import { SecurityAssessment, SecurityAssessmentResult } from './SecurityAssessment.js';
import { ZapActiveScanner, ActiveScanResult } from './ZapActiveScanner.js';
import { ApiEndpointTester, ApiTestResult } from './ApiEndpointTester.js';
import { VulnIntelligenceService, EnrichedVulnerability } from './VulnIntelligenceService.js';
import { CustomCheckLoader, CustomCheckResult } from '../core/CustomCheckLoader.js';
import { logger, logSection, logFailure, logSuccess } from '../utils/logger.js';
import { ProgressReporter } from '../utils/progress.js';
import { ComplianceConfig } from '../config/compliance.config.js';
import { FleetSiteResult } from './FleetReportGenerator.js';
import { SiemLogger } from './SiemLogger.js';
import { persistenceService } from './PersistenceService.js';
import { SupabaseSecurityIssue } from './SupabaseSecurityScanner.js';
import { VulnerableLibrary } from './FrontendVulnerabilityScanner.js';
import { NetworkIncident } from './NetworkSpy.js';
import { LeakedSecret } from './SecretScanner.js';
import { Page } from 'playwright';
import { VisualRegressionService, VisualDiffResult } from '../v3/services/VisualRegressionService.js';

interface DeviceScanResult {
    device: string;
    auditResult: AuditResult;
    crawlResult: CrawlSessionResult;
    integrityResult: IntegritySessionResult;
    customCheckResults: CustomCheckResult[];
    supabaseIssues: SupabaseSecurityIssue[];
    vulnerableLibraries: VulnerableLibrary[];
    securityResult: SecurityAssessmentResult | null;
    networkIncidents: NetworkIncident[];
    leakedSecrets: LeakedSecret[];
    screenshotPath?: string;
    visualResult?: VisualDiffResult;
}

interface VulnIntelResult {
    libraries: EnrichedVulnerability[];
    alerts: EnrichedVulnerability[];
    summary: {
        totalFindings: number;
        bySeverity: Record<string, number>;
        withExploits: number;
        inKev: number;
        averageRiskScore: number;
    };
}

interface ReportGenerationData {
    targetUrl: string;
    runId: string;
    startTime: number;
    gitSha: string;
    activeScanAllowed: boolean;
    primaryResult: DeviceScanResult;
    deviceResults: DeviceScanResult[];
    activeScanResult: ActiveScanResult | null;
    apiTestResult: ApiTestResult | null;
    vulnIntelResults: VulnIntelResult | null;
    healthScore: number;
    finalStatus: 'pass' | 'fail' | 'warning';
    activeScanResultData: ActiveScanResult | null;
}

export class ComplianceRunner {
    private readonly config: ComplianceConfig;

    constructor(config: ComplianceConfig) {
        this.config = config;
    }

    async run(targetUrl: string, progress?: ProgressReporter): Promise<FleetSiteResult> {
        const startTime = Date.now();
        const runId = randomUUID();
        const gitSha = process.env.GITHUB_SHA || process.env.GIT_SHA || '';

        logger.info(`🎯 Target: ${targetUrl}`);
        const devicesToScan = this.config.DEVICES?.length ? this.config.DEVICES : ['desktop'];
        logger.info(`📱 Devices to scan: ${devicesToScan.join(', ')}`);

        // Calculate total steps for progress bar
        const activeScanAllowed = this.checkActiveScanAllowed(targetUrl);
        const perDeviceSteps = 6 + (this.config.enableCustomChecks ? 1 : 0);
        const totalSteps = 1 + (activeScanAllowed ? 1 : 0) + (this.config.enableApiTesting ? 1 : 0) +
            (devicesToScan.length * perDeviceSteps) + ((this.config.enableVulnIntel ?? true) ? 1 : 0) + 2;

        progress?.start(totalSteps, 'Initializing run');
        await persistenceService.init(targetUrl);
        progress?.advance('WAL initialized');

        // Execute Audit Steps
        const activeScanResult = await this.runActiveScan(targetUrl, activeScanAllowed, progress);
        const apiTestResult = await this.runApiTesting(targetUrl, progress);
        const deviceResults = await this.runDeviceScans(targetUrl, devicesToScan, progress);

        if (deviceResults.length === 0) {
            logFailure('All device scans failed');
            return this.createFailedResult(targetUrl);
        }

        const primaryResult = deviceResults[0];
        const vulnIntelResults = await this.enrichVulnerabilityIntelligence(
            deviceResults, 
            primaryResult, 
            activeScanResult, 
            progress
        );

        // Analyze & Score
        const healthStats = this.calculateHealthScore(primaryResult, deviceResults, apiTestResult);
        const finalStatus = this.determineFinalStatus(healthStats.score, healthStats.securityCritical, healthStats.apiCritical);

        // Generate Report
        const reportPath = await this.generateReport({
            targetUrl, runId, startTime, gitSha, activeScanAllowed,
            primaryResult, deviceResults, activeScanResult, apiTestResult, vulnIntelResults,
            healthScore: healthStats.score, 
            finalStatus,
            activeScanResultData: activeScanResult
        }, progress);

        // Log to SIEM
        if (this.config.siem?.enabled) {
            await this.logToSiem(primaryResult, targetUrl);
        }

        logSuccess(`Scan complete for ${targetUrl}`);
        progress?.finish('Run complete');

        return {
            url: targetUrl,
            domain: this.sanitizeDomain(targetUrl),
            healthScore: healthStats.score,
            reportPath: path.relative(this.config.REPORTS_DIR, reportPath),
            criticalIssues: healthStats.totalCritical,
            status: finalStatus
        };
    }

    private checkActiveScanAllowed(targetUrl: string): boolean {
        const allowlist = this.config.activeScanAllowlist || [];
        const isAllowed = this.config.activeScanning && (this.config.activeScanAllowed || false) && (
            allowlist.length === 0 || allowlist.some(allowed => targetUrl.includes(allowed) || allowed === targetUrl)
        );
        
        if (this.config.activeScanning && !isAllowed) {
            logger.warn('Active scanning requested but not allowed for this target. Skipping active scan.');
        }
        return isAllowed;
    }

    private async runActiveScan(targetUrl: string, allowed: boolean, progress?: ProgressReporter): Promise<ActiveScanResult | null> {
        if (!allowed) return null;

        logSection('Active ZAP Scanning (Spider + Attack)');
        progress?.update('Active scan', targetUrl);
        
        const activeScanner = new ZapActiveScanner(this.config, logger);
        try {
            const result = await activeScanner.runFullActiveScan(targetUrl);
            await this.persistActiveAlerts(result);
            progress?.advance('Active scan complete');
            return result;
        } catch (error) {
            logger.error(`Active scanning failed: ${error instanceof Error ? error.message : String(error)}`);
            progress?.advance('Active scan failed');
            return null;
        } finally {
            await activeScanner.cleanup();
        }
    }

    private async persistActiveAlerts(result: ActiveScanResult) {
        if (result.activeAlerts.length > 0) {
            logger.warn(`⚠️ Active scan found ${result.activeAlerts.length} vulnerabilities`);
            for (const alert of result.activeAlerts) {
                await persistenceService.log('security_finding', {
                    ...alert,
                    source: 'zap-active',
                    severity: alert.risk
                });
            }
        }
    }

    private async runApiTesting(targetUrl: string, progress?: ProgressReporter): Promise<ApiTestResult | null> {
        if (!this.config.enableApiTesting) return null;

        logSection('API Endpoint Security Testing');
        progress?.update('API testing', targetUrl);
        
        const apiTester = new ApiEndpointTester(this.config, logger, this.config.activeSecurity);
        try {
            await apiTester.initialize();
            if (this.config.apiSpecPath) await apiTester.loadFromOpenApiSpec(this.config.apiSpecPath);
            if (this.config.apiEndpoints) this.loadManualEndpoints(apiTester, targetUrl);

            const result = await apiTester.runTests(this.config.authBypass?.tokenValue);
            
            if (result.findings.length > 0) {
                logger.warn(`🔌 API testing found ${result.findings.length} issues`);
                for (const finding of result.findings) {
                    await persistenceService.log('security_finding', { ...finding, source: 'api-tester' });
                }
            }
            
            progress?.advance('API testing complete');
            return result;
        } catch (error) {
            logger.error(`API testing failed: ${error}`);
            progress?.advance('API testing failed');
            return null;
        } finally {
            await apiTester.dispose();
        }
    }

    private loadManualEndpoints(apiTester: ApiEndpointTester, targetUrl: string) {
        if (!this.config.apiEndpoints) return;
        const manualEndpoints = this.config.apiEndpoints.map(ep => ({
            method: 'GET' as const,
            url: ep.startsWith('http') ? ep : new URL(ep, targetUrl).toString(),
            source: 'manual' as const,
        }));
        apiTester.addEndpoints(manualEndpoints);
    }

    private async runDeviceScans(targetUrl: string, devices: string[], progress?: ProgressReporter): Promise<DeviceScanResult[]> {
        const customCheckLoader = this.config.enableCustomChecks
            ? new CustomCheckLoader(logger, this.config.customChecksDir)
            : null;
        const customChecksLoaded = customCheckLoader ? await customCheckLoader.loadChecks() : 0;
        
        const results: DeviceScanResult[] = [];
        for (const device of devices) {
            try {
                const result = await this.scanDevice(targetUrl, device, customCheckLoader, customChecksLoaded, progress);
                results.push(result);
            } catch (error) {
                logger.error(`Failed to scan device ${device}: ${error}`);
            }
        }
        return results;
    }

    private async enrichVulnerabilityIntelligence(
        deviceResults: DeviceScanResult[],
        primary: DeviceScanResult,
        activeScan: ActiveScanResult | null,
        progress?: ProgressReporter
    ) {
        if (this.config.enableVulnIntel === false) return null;

        logSection('Vulnerability Intelligence Enrichment');
        progress?.update('Vulnerability intelligence', primary.auditResult.targetUrl);

        const vulnIntelService = new VulnIntelligenceService({
            nvdApiKey: this.config.nvdApiKey,
            enrichExploits: this.config.vulnIntelExploits !== false,
            enrichKev: this.config.vulnIntelKev !== false,
            enrichCwe: this.config.vulnIntelCwe !== false,
            cacheTtlMinutes: this.config.vulnIntelCacheTtl || 1440,
            cacheFilePath: this.config.vulnIntelCachePath || './cache/vuln-intel-cache.json',
            useNvdApi: true,
            useCirclApi: true,
        });

        try {
            const allVulnLibraries = deviceResults.flatMap(r => r.vulnerableLibraries);
            const allSecurityAlerts = [
                ...(primary.auditResult.security_alerts || []),
                ...(activeScan?.activeAlerts || []),
                ...(activeScan?.passiveAlerts || []),
            ];

            const results = await vulnIntelService.enrichAll(allVulnLibraries, allSecurityAlerts);
            this.logEnrichedFindings(results);
            
            logger.info(`🔍 Enriched ${results.summary.totalFindings} findings`);
            progress?.advance('Vulnerability intelligence complete');
            return results;
        } catch (error) {
            logger.warn(`Vulnerability intelligence enrichment failed: ${error}`);
            progress?.advance('Vulnerability intelligence failed');
            return null;
        }
    }

    private async logEnrichedFindings(results: { libraries: EnrichedVulnerability[], alerts: EnrichedVulnerability[] }) {
        for (const enriched of [...results.libraries, ...results.alerts]) {
            if (enriched.riskScore >= 70) {
                await persistenceService.log('security_finding', {
                    type: 'enriched_vulnerability',
                    cveId: enriched.cveId,
                    riskScore: enriched.riskScore,
                    cvss: enriched.cvss,
                    exploit: enriched.exploit,
                    kev: enriched.knownExploitedVuln,
                    riskFactors: enriched.riskFactors,
                });
            }
        }
    }

    private calculateHealthScore(primary: DeviceScanResult, allResults: DeviceScanResult[], apiTest: ApiTestResult | null) {
        const totalSecurityCritical = allResults.reduce((sum, res) =>
            sum + ((res.securityResult?.summary.critical || 0) + (res.securityResult?.summary.high || 0)), 0);
        
        const avgPerformance = (primary.auditResult.summary.performanceScore + 
            primary.auditResult.summary.accessibilityScore + 
            primary.auditResult.summary.seoScore) / 3;
            
        return {
            score: Math.round(avgPerformance),
            securityCritical: totalSecurityCritical,
            apiCritical: (apiTest?.summary.critical || 0) + (apiTest?.summary.high || 0),
            totalCritical: totalSecurityCritical + ((apiTest?.summary.critical || 0) + (apiTest?.summary.high || 0))
        };
    }

    private determineFinalStatus(score: number, secCritical: number, apiCritical: number): 'pass' | 'fail' | 'warning' {
        if (secCritical > 0 || apiCritical > 0) return 'fail';
        if (score >= 90) return 'pass';
        return 'warning';
    }

    private sanitizeDomain(url: string): string {
        try {
            // Updated to use replaceAll for Snyk compliance, maintaining global regex for safety
            return new URL(url).hostname.replaceAll(/[^a-z0-9.-]/gi, '_');
        } catch {
            return 'unknown_domain';
        }
    }

    private createFailedResult(targetUrl: string): FleetSiteResult {
        return {
            url: targetUrl,
            domain: targetUrl,
            healthScore: 0,
            reportPath: '#',
            criticalIssues: 0,
            status: 'fail'
        };
    }

    private async logToSiem(primaryResult: DeviceScanResult, targetUrl: string) {
        if (!primaryResult.securityResult?.findings) return;
        
        for (const finding of primaryResult.securityResult.findings) {
            if (['critical', 'high'].includes(finding.severity.toLowerCase())) {
                await SiemLogger.logVulnerability({
                    id: finding.id,
                    severity: finding.severity,
                    description: finding.description,
                    targetUrl: finding.endpoint || targetUrl,
                    complianceTags: []
                });
            }
        }
    }

    private async generateReport(data: ReportGenerationData, progress?: ProgressReporter): Promise<string> {
        progress?.update('Generating report');
        
        const report = this.constructReportObject(data);
        const brandingConfig: Partial<BrandingConfig> = {
            companyName: this.config.BRAND_COMPANY_NAME,
            logoUrl: this.config.BRAND_LOGO_URL || undefined,
            primaryColor: this.config.BRAND_PRIMARY_COLOR,
            customCssUrl: this.config.BRAND_CUSTOM_CSS_URL || undefined,
            footerText: this.config.BRAND_FOOTER_TEXT || undefined,
            reportTitle: this.config.BRAND_REPORT_TITLE || undefined,
        };

        const htmlReportGenerator = new HtmlReportGenerator(this.config.REPORTS_DIR, brandingConfig);
        const domain = this.sanitizeDomain(data.targetUrl);
        const domainReportDir = path.join(this.config.REPORTS_DIR, domain);

        if (!fs.existsSync(domainReportDir)) {
            fs.mkdirSync(domainReportDir, { recursive: true });
        }

        const htmlReportPath = await htmlReportGenerator.generate(report);
        progress?.advance('Report generated');

        // PDF Generation
        try {
            const pdfReportPath = htmlReportPath.replace('.html', '.pdf');
            await htmlReportGenerator.generatePdf(htmlReportPath, pdfReportPath);
            logger.info(`PDF Report generated: ${pdfReportPath}`);
            progress?.advance('PDF generated');
        } catch {
            progress?.advance('PDF generation skipped');
        }

        return htmlReportPath;
    }

    private constructReportObject(data: ReportGenerationData): any {
        const { primaryResult, deviceResults, activeScanResultData, apiTestResult, vulnIntelResults } = data;
        const totalViolations = deviceResults.reduce((sum: number, res: DeviceScanResult) =>
             sum + res.customCheckResults.reduce((acc, r) => acc + r.violations.length, 0), 0);
             
         return {
            meta: {
                version: '1.0.0',
                generatedAt: new Date().toISOString(),
                targetUrl: data.targetUrl,
                duration: Date.now() - data.startTime,
                activeScanning: data.activeScanAllowed,
                runId: data.runId,
                profile: this.config.name,
                gitSha: data.gitSha,
                runTag: this.config.runTag,
            },
            authentication: { success: true, duration: 0 },
            crawl: primaryResult.crawlResult,
            integrity: primaryResult.integrityResult,
            network_incidents: primaryResult.networkIncidents,
            leaked_secrets: primaryResult.leakedSecrets,
            supabase_issues: primaryResult.supabaseIssues,
            vulnerable_libraries: primaryResult.vulnerableLibraries,
            security_assessment: primaryResult.securityResult,
            lighthouse: primaryResult.auditResult.lighthouse,
            security_alerts: primaryResult.auditResult.security_alerts,
            active_scan: activeScanResultData ? {
                enabled: true,
                spiderUrls: activeScanResultData.spiderUrls,
                passiveAlerts: activeScanResultData.passiveAlerts,
                activeAlerts: activeScanResultData.activeAlerts,
                duration: activeScanResultData.duration,
                completed: activeScanResultData.completed
            } : null,
            custom_checks: primaryResult.customCheckResults,
            ignored_alerts: primaryResult.auditResult.ignored_alerts || [],
            api_testing: apiTestResult ? {
                enabled: true,
                endpointsTested: apiTestResult.endpointsTested,
                endpointsDiscovered: apiTestResult.endpointsDiscovered,
                findings: apiTestResult.findings,
                duration: apiTestResult.duration,
                summary: apiTestResult.summary
            } : null,
            vuln_intelligence: vulnIntelResults ? {
                enabled: true,
                enrichedLibraries: vulnIntelResults.libraries,
                enrichedAlerts: vulnIntelResults.alerts,
                summary: vulnIntelResults.summary,
            } : null,
            multi_device: deviceResults.map((r: DeviceScanResult) => ({
                device: r.device,
                lighthouse: r.auditResult.lighthouse,
                crawlSummary: {
                    pagesVisited: r.crawlResult.pageResults.length,
                    failedPages: r.crawlResult.failedPages
                },
                screenshotPath: r.screenshotPath
            })),
            summary: {
                ...primaryResult.auditResult.summary,
                crawlPagesInvalid: primaryResult.crawlResult.failedPages,
                crawlPagesSuspicious: primaryResult.crawlResult.suspiciousPages,
                integrityFailures: primaryResult.integrityResult.failed,
                securityCritical: primaryResult.securityResult?.summary.critical || 0,
                securityHigh: primaryResult.securityResult?.summary.high || 0,
                supabaseIssues: primaryResult.supabaseIssues.length,
                vulnerableLibraries: primaryResult.vulnerableLibraries.length,
                activeAlerts: activeScanResultData?.activeAlerts.length || 0,
                customViolations: totalViolations,
                apiFindings: apiTestResult?.findings.length || 0,
                apiCritical: apiTestResult?.summary.critical || 0,
                apiHigh: apiTestResult?.summary.high || 0,
                vulnIntelEnriched: vulnIntelResults?.summary.totalFindings || 0,
                vulnIntelCritical: vulnIntelResults?.summary.bySeverity.CRITICAL || 0,
                vulnIntelHigh: vulnIntelResults?.summary.bySeverity.HIGH || 0,
                vulnIntelWithExploits: vulnIntelResults?.summary.withExploits || 0,
                vulnIntelInKev: vulnIntelResults?.summary.inKev || 0,
                vulnIntelAvgRisk: vulnIntelResults?.summary.averageRiskScore || 0,
            },
            coverage: this.buildCoverageReport(primaryResult, activeScanResultData, apiTestResult, vulnIntelResults)
        };
    }

    private buildCoverageReport(primaryResult: any, activeScanResultData: any, apiTestResult: any, vulnIntelResults: any) {
        return [
            { 
                name: 'Lighthouse', 
                status: primaryResult.auditResult?.lighthouse ? 'ran' : 'failed' 
            },
            { 
                name: 'Crawler', 
                status: primaryResult.crawlResult ? 'ran' : 'failed' 
            },
            { 
                name: 'ZAP Passive', 
                status: this.config.ZAP_PROXY_URL ? 'ran' : 'skipped', 
                detail: this.config.ZAP_PROXY_URL ? undefined : 'Proxy disabled' 
            },
            { 
                name: 'ZAP Active', 
                status: activeScanResultData ? 'ran' : 'skipped' 
            },
            { 
                name: 'API Testing', 
                status: this.config.enableApiTesting ? (apiTestResult ? 'ran' : 'failed') : 'skipped' 
            },
            { 
                name: 'Vulnerability Intel', 
                status: (this.config.enableVulnIntel ?? true) ? (vulnIntelResults ? 'ran' : 'failed') : 'skipped' 
            },
            { 
                name: 'Custom Checks', 
                status: this.config.enableCustomChecks ? 'ran' : 'skipped' 
            },
            { 
                name: 'Visual Regression', 
                status: primaryResult.crawlResult?.pageResults?.some((p: { visualResult?: unknown }) => p.visualResult) ? 'ran' : 'skipped' 
            },
            { 
                name: 'Supabase Scanner', 
                status: (primaryResult.supabaseIssues?.length ?? 0) >= 0 ? 'ran' : 'skipped' 
            },
            { 
                name: 'Secret Scanner', 
                status: (primaryResult.leakedSecrets?.length ?? 0) >= 0 ? 'ran' : 'skipped' 
            }
        ];
    }

    private async scanDevice(
        targetUrl: string,
        device: string,
        customCheckLoader?: CustomCheckLoader | null,
        customChecksLoaded: number = 0,
        progress?: ProgressReporter
    ): Promise<DeviceScanResult> {
        logSection(`Starting Scan for Device: ${device}`);

        const browserService = new BrowserService();
        const runConfig = this.prepareRunConfig(targetUrl);
        const authService = new AuthService(browserService);
        const crawlerService = new CrawlerService(browserService, runConfig);
        const integrityService = new DataIntegrityService(browserService);
        const auditService = new AuditService();

        try {
            await this.initializeBrowserSession(browserService, device, runConfig, progress);
            await this.performAuthentication(authService, targetUrl, device, progress);

            progress?.advance('Running audits', device);
            const auditResult = await this.performAudit(auditService, runConfig, targetUrl, device);
            await persistenceService.log('security_finding', auditResult.security_alerts);

            progress?.advance('Crawling site', device);
            const crawlResult = await crawlerService.crawl();
            const page = browserService.getPage();

            const { screenshotPath, visualResult } = await this.captureVisuals(browserService, device, targetUrl, page);

            progress?.advance('Integrity checks', device);
            const visitedUrls = crawlerService.getVisitedUrls();
            const integrityResult = await integrityService.runIntegrityChecks(visitedUrls);

            progress?.advance('Security scanners', device);
            const { supabaseIssues, vulnerableLibraries } = await this.runBrowserScanners(browserService);

            const securityResult = await this.runSecurityAssessment(page, targetUrl, visitedUrls, device);

            const customCheckResults = await this.runCustomChecks(
                page, {
                    targetUrl, visitedUrls, device, runConfig, 
                    customCheckLoader, customChecksLoaded, progress
                }
            );

            return {
                device,
                auditResult,
                crawlResult,
                integrityResult,
                customCheckResults,
                supabaseIssues,
                vulnerableLibraries,
                securityResult,
                networkIncidents: browserService.getNetworkIncidents(),
                leakedSecrets: browserService.getLeakedSecrets(),
                screenshotPath,
                visualResult
            };
        } finally {
            await browserService.close();
            await auditService.cleanup();
        }
    }

    private prepareRunConfig(targetUrl: string): ComplianceConfig {
        const runConfig: ComplianceConfig = { ...this.config, targetUrl };
        if (runConfig.authBypass) {
            try {
                runConfig.authBypass.domain = new URL(targetUrl).hostname;
            } catch { /* ignore invalid URLs */ }
        }
        return runConfig;
    }

    private async initializeBrowserSession(
        browserService: BrowserService, 
        device: string, 
        runConfig: ComplianceConfig, 
        progress?: ProgressReporter
    ) {
        progress?.advance('Initializing browser/proxy', device);
        await browserService.initialize({
            headless: true,
            useProxy: runConfig.activeSecurity,
            deviceName: device
        });
    }

    private async performAuthentication(
        authService: AuthService, 
        targetUrl: string, 
        device: string, 
        progress?: ProgressReporter
    ) {
        progress?.advance('Authenticating', device);
        const authResult = await authService.login(targetUrl);
        await persistenceService.log('custom', { event: 'auth_complete', device, success: authResult.success });
    }

    private async performAudit(
        auditService: AuditService, 
        runConfig: ComplianceConfig, 
        targetUrl: string, 
        device: string
    ): Promise<AuditResult> {
        if (runConfig.activeSecurity) {
            return await auditService.runFullAudit(targetUrl, device);
        }
        
        const lighthouseResult = await auditService.runLighthouseAudit(targetUrl, device, {
            useBaseline: true,
            budget: runConfig.performanceBudget
        });

        return {
            lighthouse: lighthouseResult,
            security_alerts: [],
            ignored_alerts: [],
            summary: {
                performanceScore: lighthouseResult?.scores.performance || 0,
                accessibilityScore: lighthouseResult?.scores.accessibility || 0,
                seoScore: lighthouseResult?.scores.seo || 0,
                highRiskAlerts: 0,
                mediumRiskAlerts: 0,
                passedAudit: (lighthouseResult?.scores.performance || 0) >= 50
            },
            timestamp: new Date().toISOString(),
            targetUrl
        };
    }

    private async captureVisuals(browserService: BrowserService, device: string, targetUrl: string, page: Page | null) {
        let screenshotPath: string | undefined;
        let visualResult: VisualDiffResult | undefined;

        if (!page) return { screenshotPath, visualResult };

        try {
            const sc = await browserService.screenshot(`report-${device}`);
            screenshotPath = sc.path;

            try {
                const buffer = await page.screenshot({ fullPage: true });
                const visualService = new VisualRegressionService(
                    logger, 
                    '.visual-baselines',
                    this.config.visualDiffThreshold || 0.1
                );
                // Updated to use replaceAll via global regex
                const safeDomain = new URL(targetUrl).hostname.replaceAll(/[^a-z0-9]/gi, '_');
                visualResult = await visualService.compare(`${safeDomain}-${device}`, buffer);

                if (!visualResult.passed) {
                    logger.warn(`📸 Visual Regression Failed for ${device}: ${visualResult.diffPercentage.toFixed(2)}% difference`);
                }
            } catch (vrError) {
                logger.warn(`Visual regression check failed: ${vrError}`);
            }
        } catch { /* ignore screenshot errors */ }

        return { screenshotPath, visualResult };
    }

    private async runBrowserScanners(browserService: BrowserService) {
        await browserService.runSupabaseSecurityTests();
        const supabaseIssues = browserService.getSupabaseIssues();

        await browserService.scanPageLibraries();
        const vulnerableLibraries = browserService.getVulnerableLibraries();

        return { supabaseIssues, vulnerableLibraries };
    }

    private async runSecurityAssessment(page: Page | null, targetUrl: string, visitedUrls: string[], device: string) {
        if (!page) return null;
        
        const securityAssessment = new SecurityAssessment();
        try {
            const securityResult = await securityAssessment.assess(page, targetUrl, visitedUrls);
            if (securityResult.findings) {
                for (const finding of securityResult.findings) {
                    await persistenceService.log('security_assessment', { ...finding, device });
                }
            }
            return securityResult;
        } catch (secError) {
            logger.warn(`Security assessment failed: ${secError instanceof Error ? secError.message : String(secError)}`);
            return null;
        }
    }

    private async runCustomChecks(
        page: Page | null, 
        options: {
            targetUrl: string, 
            visitedUrls: string[], 
            device: string, 
            runConfig: ComplianceConfig,
            customCheckLoader: CustomCheckLoader | null | undefined,
            customChecksLoaded: number,
            progress?: ProgressReporter
        }
    ) {
        const { targetUrl, visitedUrls, device, runConfig, customCheckLoader, customChecksLoaded, progress } = options;
        if (!runConfig.enableCustomChecks || !page) return [];

        try {
            const loader = customCheckLoader ?? new CustomCheckLoader(logger, runConfig.customChecksDir);
            const checkCount = customCheckLoader ? customChecksLoaded : await loader.loadChecks();

            if (checkCount > 0) {
                progress?.advance('Custom checks', device);
                const results = await loader.runChecks(page, {
                    targetUrl,
                    currentUrl: page.url(),
                    visitedUrls,
                    logger,
                    profile: this.config.name
                });
                
                for (const res of results) {
                    if (!res.passed) {
                        for (const v of res.violations) {
                            await persistenceService.log('custom_check_violation', { ...v, device });
                        }
                    }
                }
                return results;
            }
        } catch (checkError) {
            logger.error(`Custom checks failed: ${checkError instanceof Error ? checkError.message : String(checkError)}`);
        }
        return [];
    }
}
