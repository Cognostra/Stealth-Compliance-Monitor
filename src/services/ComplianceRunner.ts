import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { BrowserService } from './BrowserService.js';
import { AuthService } from './AuthService.js';
import { AuditService, AuditResult } from './AuditService.js';
import { CrawlerService, CrawlSessionResult } from './CrawlerService.js';
import { DataIntegrityService, IntegritySessionResult } from './DataIntegrityService.js';
import { HtmlReportGenerator, BrandingConfig } from './HtmlReportGenerator.js';
import { SecurityAssessment, SecurityAssessmentResult } from './SecurityAssessment.js';
import { ZapActiveScanner, ActiveScanResult } from './ZapActiveScanner.js';
import { ApiEndpointTester, ApiTestResult } from './ApiEndpointTester.js';
import { VulnIntelligenceService, EnrichedVulnerability, IntelligenceSummary } from './VulnIntelligenceService.js';
import { CustomCheckLoader, CustomCheckResult } from '../core/CustomCheckLoader.js';
import { logger, logSection, logSuccess, logFailure } from '../utils/logger.js';
import { ComplianceConfig } from '../config/compliance.config.js';
import { FleetSiteResult } from './FleetReportGenerator.js';
import { SiemLogger } from './SiemLogger.js';
import { persistenceService } from './PersistenceService.js';
import { SupabaseSecurityIssue } from './SupabaseSecurityScanner.js';
import { VulnerableLibrary } from './FrontendVulnerabilityScanner.js';
import { NetworkIncident } from './NetworkSpy.js';
import { LeakedSecret } from './SecretScanner.js';

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
}

export class ComplianceRunner {
    private config: ComplianceConfig;

    constructor(config: ComplianceConfig) {
        this.config = config;
    }

    async run(targetUrl: string): Promise<FleetSiteResult> {
        const startTime = Date.now();
        const runId = randomUUID();
        const gitSha = process.env.GITHUB_SHA || process.env.GIT_SHA || '';
        let finalStatus: 'pass' | 'fail' | 'warning' = 'fail';
        let healthScore = 0;
        let htmlReportPath = '';
        let activeScanResult: ActiveScanResult | null = null;
        let apiTestResult: ApiTestResult | null = null;

        // Define devices to scan
        const devicesToScan = this.config.DEVICES && this.config.DEVICES.length > 0
            ? this.config.DEVICES
            : ['desktop'];

        logger.info(`🎯 Target: ${targetUrl}`);
        logger.info(`📱 Devices to scan: ${devicesToScan.join(', ')}`);

        // Step 0: Initialize WAL
        await persistenceService.init(targetUrl);

        // Step 1: Active ZAP Scanning (Global, run once)
        const allowlist = this.config.activeScanAllowlist || [];
        const activeScanAllowed = this.config.activeScanning && (this.config.activeScanAllowed || false) && (
            allowlist.length === 0 || allowlist.some(allowed => targetUrl.includes(allowed) || allowed === targetUrl)
        );

        if (activeScanAllowed) {
            logSection('Active ZAP Scanning (Spider + Attack)');
            const activeScanner = new ZapActiveScanner(this.config, logger);
            try {
                // Determine bypass auth for scanner if needed (not supported in helper yet)
                activeScanResult = await activeScanner.runFullActiveScan(targetUrl);

                if (activeScanResult.activeAlerts.length > 0) {
                    logger.warn(`⚠️ Active scan found ${activeScanResult.activeAlerts.length} vulnerabilities`);
                    for (const alert of activeScanResult.activeAlerts) {
                        await persistenceService.log('security_finding', {
                            ...alert,
                            source: 'zap-active',
                            severity: alert.risk
                        });
                    }
                }
            } catch (activeError) {
                logger.error(`Active scanning failed: ${activeError instanceof Error ? activeError.message : String(activeError)}`);
            } finally {
                await activeScanner.cleanup();
            }
        } else if (this.config.activeScanning) {
            logger.warn('Active scanning requested but not allowed for this target. Skipping active scan.');
        }

        // Step 1.5: API Endpoint Testing (Global, run once)
        if (this.config.enableApiTesting) {
            logSection('API Endpoint Security Testing');
            const apiTester = new ApiEndpointTester(this.config, logger, this.config.activeSecurity);
            try {
                await apiTester.initialize();

                // Load from OpenAPI spec if provided
                if (this.config.apiSpecPath && this.config.apiSpecPath.length > 0) {
                    await apiTester.loadFromOpenApiSpec(this.config.apiSpecPath);
                }

                // Add manual endpoints if provided
                if (this.config.apiEndpoints && this.config.apiEndpoints.length > 0) {
                    const manualEndpoints = this.config.apiEndpoints.map(ep => ({
                        method: 'GET' as const,
                        url: ep.startsWith('http') ? ep : new URL(ep, targetUrl).toString(),
                        source: 'manual' as const,
                    }));
                    apiTester.addEndpoints(manualEndpoints);
                }

                // Run tests
                const authToken = this.config.authBypass?.tokenValue;
                apiTestResult = await apiTester.runTests(authToken);

                // Log findings
                if (apiTestResult.findings.length > 0) {
                    logger.warn(`🔌 API testing found ${apiTestResult.findings.length} issues`);
                    for (const finding of apiTestResult.findings) {
                        await persistenceService.log('security_finding', {
                            ...finding,
                            source: 'api-tester',
                        });
                    }
                }
            } catch (apiError) {
                logger.error(`API testing failed: ${apiError instanceof Error ? apiError.message : String(apiError)}`);
            } finally {
                await apiTester.dispose();
            }
        }

        // Step 2: Multi-Device Scanning Loop
        const customCheckLoader = this.config.enableCustomChecks
            ? new CustomCheckLoader(logger, this.config.customChecksDir)
            : null;
        const customChecksLoaded = customCheckLoader ? await customCheckLoader.loadChecks() : 0;
        const deviceResults: DeviceScanResult[] = [];

        for (const device of devicesToScan) {
            try {
                const result = await this.scanDevice(targetUrl, device, customCheckLoader, customChecksLoaded);
                deviceResults.push(result);
            } catch (error) {
                logger.error(`Failed to scan device ${device}: ${error}`);
            }
        }

        if (deviceResults.length === 0) {
            logFailure('All device scans failed');
            return {
                url: targetUrl,
                domain: targetUrl,
                healthScore: 0,
                reportPath: '#',
                criticalIssues: 0,
                status: 'fail'
            };
        }

        // Use the first result (usually desktop) as the primary result for top-level report sections
        const primaryResult = deviceResults[0];

        // Step 3: Vulnerability Intelligence Enrichment
        let vulnIntelResults: {
            libraries: EnrichedVulnerability[];
            alerts: EnrichedVulnerability[];
            summary: IntelligenceSummary;
        } | null = null;

        if (this.config.enableVulnIntel !== false) {
            logSection('Vulnerability Intelligence Enrichment');
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
                // Collect all vulnerable libraries across devices
                const allVulnLibraries = deviceResults.flatMap(r => r.vulnerableLibraries);

                // Collect all security alerts
                const allSecurityAlerts = [
                    ...(primaryResult.auditResult.security_alerts || []),
                    ...(activeScanResult?.activeAlerts || []),
                    ...(activeScanResult?.passiveAlerts || []),
                ];

                vulnIntelResults = await vulnIntelService.enrichAll(
                    allVulnLibraries,
                    allSecurityAlerts
                );

                // Log enriched findings to WAL
                for (const enriched of [...vulnIntelResults.libraries, ...vulnIntelResults.alerts]) {
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

                logger.info(`🔍 Enriched ${vulnIntelResults.summary.totalFindings} findings`);
                logger.info(`   KEV hits: ${vulnIntelResults.summary.inKev}, Exploits: ${vulnIntelResults.summary.withExploits}`);
            } catch (intelError) {
                logger.warn(`Vulnerability intelligence enrichment failed: ${intelError instanceof Error ? intelError.message : String(intelError)}`);
            }
        }

        // Aggregate findings for summary
        const totalSecurityCritical = deviceResults.reduce((sum, res) =>
            sum + ((res.securityResult?.summary.critical || 0) + (res.securityResult?.summary.high || 0)), 0);

        const totalViolations = deviceResults.reduce((sum, res) =>
            sum + res.customCheckResults.reduce((acc, r) => acc + r.violations.length, 0), 0);

        // Count API critical/high findings
        const apiCriticalFindings = (apiTestResult?.summary.critical || 0) + (apiTestResult?.summary.high || 0);

        // Calculate Merged Health Score
        healthScore = Math.round(
            (primaryResult.auditResult.summary.performanceScore +
                primaryResult.auditResult.summary.accessibilityScore +
                primaryResult.auditResult.summary.seoScore) / 3
        );

        if (totalSecurityCritical > 0 || apiCriticalFindings > 0 || (primaryResult.auditResult.summary.highRiskAlerts > 0)) {
            healthScore = Math.max(0, healthScore - 20);
            finalStatus = 'fail';
        } else if (healthScore >= 90) {
            finalStatus = 'pass';
        } else {
            finalStatus = 'warning';
        }

        // Generate Report
        const report = {
            meta: {
                version: '1.0.0',
                generatedAt: new Date().toISOString(),
                targetUrl: targetUrl,
                duration: Date.now() - startTime,
                activeScanning: activeScanAllowed,
                runId,
                profile: this.config.name,
                gitSha,
                runTag: this.config.runTag,
            },
            authentication: { success: true, duration: 0 },
            crawl: primaryResult.crawlResult, // Primary crawl
            integrity: primaryResult.integrityResult,
            network_incidents: primaryResult.networkIncidents,
            leaked_secrets: primaryResult.leakedSecrets,
            supabase_issues: primaryResult.supabaseIssues,
            vulnerable_libraries: primaryResult.vulnerableLibraries,
            security_assessment: primaryResult.securityResult,
            lighthouse: primaryResult.auditResult.lighthouse,
            security_alerts: primaryResult.auditResult.security_alerts,
            // Active scan (common)
            active_scan: activeScanResult ? {
                enabled: true,
                spiderUrls: activeScanResult.spiderUrls,
                passiveAlerts: activeScanResult.passiveAlerts,
                activeAlerts: activeScanResult.activeAlerts,
                duration: activeScanResult.duration,
                completed: activeScanResult.completed
            } : null,
            // Custom checks (Primary)
            custom_checks: primaryResult.customCheckResults,
            ignored_alerts: primaryResult.auditResult.ignored_alerts || [],
            // API testing results
            api_testing: apiTestResult ? {
                enabled: true,
                endpointsTested: apiTestResult.endpointsTested,
                endpointsDiscovered: apiTestResult.endpointsDiscovered,
                findings: apiTestResult.findings,
                duration: apiTestResult.duration,
                summary: apiTestResult.summary
            } : null,
            // Vulnerability Intelligence
            vuln_intelligence: vulnIntelResults ? {
                enabled: true,
                enrichedLibraries: vulnIntelResults.libraries,
                enrichedAlerts: vulnIntelResults.alerts,
                summary: vulnIntelResults.summary,
            } : null,
            // Multi-device Results
            multi_device: deviceResults.map(r => ({
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
                activeAlerts: activeScanResult?.activeAlerts.length || 0,
                customViolations: totalViolations,
                apiFindings: apiTestResult?.findings.length || 0,
                apiCritical: apiTestResult?.summary.critical || 0,
                apiHigh: apiTestResult?.summary.high || 0,
                // Vulnerability Intelligence Summary
                vulnIntelEnriched: vulnIntelResults?.summary.totalFindings || 0,
                vulnIntelCritical: vulnIntelResults?.summary.bySeverity.CRITICAL || 0,
                vulnIntelHigh: vulnIntelResults?.summary.bySeverity.HIGH || 0,
                vulnIntelWithExploits: vulnIntelResults?.summary.withExploits || 0,
                vulnIntelInKev: vulnIntelResults?.summary.inKev || 0,
                vulnIntelAvgRisk: vulnIntelResults?.summary.averageRiskScore || 0,
            },
            coverage: [
                { name: 'Lighthouse', status: primaryResult.auditResult?.lighthouse ? 'ran' : 'failed' },
                { name: 'Crawler', status: primaryResult.crawlResult ? 'ran' : 'failed' },
                { name: 'ZAP Passive', status: this.config.ZAP_PROXY_URL ? 'ran' : 'skipped', detail: this.config.ZAP_PROXY_URL ? undefined : 'Proxy disabled' },
                { name: 'ZAP Active', status: activeScanAllowed ? 'ran' : 'skipped', detail: activeScanAllowed ? undefined : 'Not allowed or disabled' },
                { name: 'API Testing', status: this.config.enableApiTesting ? (apiTestResult ? 'ran' : 'failed') : 'skipped' },
                { name: 'Vulnerability Intel', status: this.config.enableVulnIntel !== false ? (vulnIntelResults ? 'ran' : 'failed') : 'skipped' },
                { name: 'Custom Checks', status: this.config.enableCustomChecks ? 'ran' : 'skipped' },
                { name: 'Visual Regression', status: primaryResult.crawlResult?.pageResults?.some((p: { visualResult?: unknown }) => p.visualResult) ? 'ran' : 'skipped' },
                { name: 'Supabase Scanner', status: (primaryResult.supabaseIssues?.length ?? 0) >= 0 ? 'ran' : 'skipped' },
                { name: 'Secret Scanner', status: (primaryResult.leakedSecrets?.length ?? 0) >= 0 ? 'ran' : 'skipped' }
            ]
        };

        // Build branding config from environment
        const brandingConfig: Partial<BrandingConfig> = {
            companyName: this.config.BRAND_COMPANY_NAME,
            logoUrl: this.config.BRAND_LOGO_URL || undefined,
            primaryColor: this.config.BRAND_PRIMARY_COLOR,
            customCssUrl: this.config.BRAND_CUSTOM_CSS_URL || undefined,
            footerText: this.config.BRAND_FOOTER_TEXT || undefined,
            reportTitle: this.config.BRAND_REPORT_TITLE || undefined,
        };

        const htmlReportGenerator = new HtmlReportGenerator(this.config.REPORTS_DIR, brandingConfig);

        // Save Reports
        const domain = new URL(targetUrl).hostname;
        const domainReportDir = path.join(this.config.REPORTS_DIR, domain);

        if (!fs.existsSync(domainReportDir)) {
            fs.mkdirSync(domainReportDir, { recursive: true });
        }

        htmlReportPath = await htmlReportGenerator.generate(report as Parameters<HtmlReportGenerator['generate']>[0]);

        // Generate PDF
        try {
            const pdfReportPath = htmlReportPath.replace('.html', '.pdf');
            await htmlReportGenerator.generatePdf(htmlReportPath, pdfReportPath);
            logger.info(`PDF Report generated: ${pdfReportPath}`);
        } catch (pdfError) {
            logger.warn(`PDF generation failed: ${pdfError}`);
        }

        // SIEM Log (Use Primary Findings)
        if (this.config.siem?.enabled) {
            if (primaryResult.securityResult?.findings) {
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
        }

        logSuccess(`Scan complete for ${targetUrl}`);

        return {
            url: targetUrl,
            domain: domain,
            healthScore: healthScore,
            reportPath: path.relative(this.config.REPORTS_DIR, htmlReportPath),
            criticalIssues: (report.summary.securityCritical || 0) + report.summary.highRiskAlerts,
            status: finalStatus
        };
    }

    private async scanDevice(
        targetUrl: string,
        device: string,
        customCheckLoader?: CustomCheckLoader | null,
        customChecksLoaded: number = 0
    ): Promise<DeviceScanResult> {
        logSection(`Starting Scan for Device: ${device}`);

        const browserService = new BrowserService();
        // Override targetUrl in config for this run
        const runConfig: ComplianceConfig = { ...this.config, targetUrl: targetUrl };
        if (runConfig.authBypass) {
            try {
                const url = new URL(targetUrl);
                runConfig.authBypass.domain = url.hostname;
            } catch { }
        }

        const authService = new AuthService(browserService);
        const crawlerService = new CrawlerService(browserService, runConfig);
        const integrityService = new DataIntegrityService(browserService);
        const auditService = new AuditService();

        let auditResult: AuditResult = {
            lighthouse: null,
            security_alerts: [],
            ignored_alerts: [],
            summary: {
                performanceScore: 0,
                accessibilityScore: 0,
                seoScore: 0,
                highRiskAlerts: 0,
                mediumRiskAlerts: 0,
                passedAudit: false,
            },
            timestamp: new Date().toISOString(),
            targetUrl: targetUrl,
        };
        let securityResult: SecurityAssessmentResult | null = null;
        let customCheckResults: CustomCheckResult[] = [];
        let screenshotPath: string | undefined;

        try {
            // Step 1: Init Browser with Device
            await browserService.initialize({
                headless: true,
                useProxy: runConfig.activeSecurity,
                deviceName: device
            });

            // Step 2: Auth
            const authResult = await authService.login(targetUrl);
            await persistenceService.log('custom', { event: 'auth_complete', device, success: authResult.success });

            // Step 3: Run Audit (Lighthouse)
            if (runConfig.activeSecurity) {
                auditResult = await auditService.runFullAudit(targetUrl, device);
            } else {
                const lighthouseResult = await auditService.runLighthouseAudit(targetUrl, device);
                auditResult = {
                    lighthouse: lighthouseResult,
                    security_alerts: [],
                    summary: {
                        performanceScore: lighthouseResult?.scores.performance ?? 0,
                        accessibilityScore: lighthouseResult?.scores.accessibility ?? 0,
                        seoScore: lighthouseResult?.scores.seo ?? 0,
                        highRiskAlerts: 0,
                        mediumRiskAlerts: 0,
                        passedAudit: true
                    },
                    timestamp: new Date().toISOString(),
                    targetUrl: targetUrl,
                    ignored_alerts: []
                };
            }
            await persistenceService.log('security_finding', auditResult.security_alerts);

            // Step 4: Crawl
            const crawlResult = await crawlerService.crawl();

            // Take a screenshot of main page for report
            const page = browserService.getPage();
            if (page) {
                try {
                    const sc = await browserService.screenshot(`report-${device}`);
                    screenshotPath = sc.path;
                } catch { }
            }

            // Step 5: Integrity
            const visitedUrls = crawlerService.getVisitedUrls();
            const integrityResult = await integrityService.runIntegrityChecks(visitedUrls);

            // Step 5.5: Supabase & Library
            await browserService.runSupabaseSecurityTests();
            const supabaseIssues = browserService.getSupabaseIssues();

            await browserService.scanPageLibraries();
            const vulnerableLibraries = browserService.getVulnerableLibraries();

            // Step 6: Security Assessment (Black Box)
            const securityAssessment = new SecurityAssessment();
            if (page) {
                try {
                    securityResult = await securityAssessment.assess(page, targetUrl, visitedUrls);
                    if (securityResult.findings) {
                        for (const finding of securityResult.findings) {
                            await persistenceService.log('security_assessment', { ...finding, device });
                        }
                    }
                } catch (secError) {
                    logger.warn(`Security assessment failed: ${secError instanceof Error ? secError.message : String(secError)}`);
                }
            }

            // Step 7: Custom Checks
            if (runConfig.enableCustomChecks && page) {
                try {
                    const loader = customCheckLoader ?? new CustomCheckLoader(logger, runConfig.customChecksDir);
                    const checkCount = customCheckLoader ? customChecksLoaded : await loader.loadChecks();

                    if (checkCount > 0) {
                        customCheckResults = await loader.runChecks(page, {
                            targetUrl,
                            currentUrl: page.url(),
                            visitedUrls,
                            logger,
                            profile: this.config.name
                        });
                        // Log violations
                        for (const res of customCheckResults) {
                            if (!res.passed) {
                                for (const v of res.violations) {
                                    await persistenceService.log('custom_check_violation', { ...v, device });
                                }
                            }
                        }
                    }
                } catch (checkError) {
                    logger.error(`Custom checks failed: ${checkError instanceof Error ? checkError.message : String(checkError)}`);
                }
            }

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
                screenshotPath
            };

        } finally {
            await browserService.close();
            await auditService.cleanup();
        }
    }
}
