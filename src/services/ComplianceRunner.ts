import * as fs from 'fs';
import * as path from 'path';
import { BrowserService } from './BrowserService';
import { AuthService } from './AuthService';
import { AuditService } from './AuditService';
import { CrawlerService } from './CrawlerService';
import { DataIntegrityService } from './DataIntegrityService';
import { ReportGenerator } from './ReportGenerator';
import { HtmlReportGenerator } from './HtmlReportGenerator';
import { SecurityAssessment } from './SecurityAssessment';
import { logger, logSection, logSuccess, logFailure } from '../utils/logger';
import { ComplianceConfig } from '../config/compliance.config';
import { FleetSiteResult } from './FleetReportGenerator';
import { SiemLogger } from './SiemLogger';
import { persistenceService } from './PersistenceService';

export class ComplianceRunner {
    private config: ComplianceConfig;

    constructor(config: ComplianceConfig) {
        this.config = config;
    }

    async run(targetUrl: string): Promise<FleetSiteResult> {
        // Initialize services
        const browserService = new BrowserService();
        const authService = new AuthService(browserService);
        const crawlerService = new CrawlerService(browserService, { ...this.config, targetUrl: targetUrl } as any);
        const integrityService = new DataIntegrityService(browserService);
        const auditService = new AuditService();
        const reportGenerator = new ReportGenerator();
        const htmlReportGenerator = new HtmlReportGenerator(this.config.REPORTS_DIR);

        // Override targetUrl in config for this run
        const runConfig = { ...this.config, targetUrl: targetUrl };
        if (runConfig.authBypass) {
            // We might need to adjust auth domain if multiple sites + sso
            // For now assume auth config is global or per-site config needs enhancement
            try {
                const url = new URL(targetUrl);
                runConfig.authBypass.domain = url.hostname;
            } catch { }
        }

        const startTime = Date.now();
        let auditResult: any = {};
        let securityCritical = 0;
        let finalStatus: 'pass' | 'fail' | 'warning' = 'fail';
        let healthScore = 0;
        let htmlReportPath = '';

        try {
            logSection(`Starting Scan: ${targetUrl}`);

            // Step 0: Initialize WAL
            await persistenceService.init(targetUrl);

            // Step 1: Initialize Browser
            await browserService.initialize({
                headless: true,
                useProxy: runConfig.activeSecurity
            });

            // Step 2: Authentication
            const authResult = await authService.login(targetUrl);
            await persistenceService.log('custom', { event: 'auth_complete', success: authResult.success });

            // Step 3: Run Audits
            if (runConfig.activeSecurity) {
                auditResult = await auditService.runFullAudit();
            } else {
                const lighthouseResult = await auditService.runLighthouseAudit(targetUrl);
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

            // Step 4: Deep Crawl
            const crawlResult = await crawlerService.crawl();
            await persistenceService.log('page_result', crawlResult.pageResults);

            // Step 5: Data Integrity
            const visitedUrls = crawlerService.getVisitedUrls();
            const integrityResult = await integrityService.runIntegrityChecks(visitedUrls);
            await persistenceService.log('custom', { event: 'integrity_complete', ...integrityResult });

            // Step 5.5: Supabase & Library Scan
            await browserService.runSupabaseSecurityTests();
            const supabaseIssues = browserService.getSupabaseIssues();
            for (const issue of supabaseIssues) await persistenceService.log('supabase_issue', issue);

            await browserService.scanPageLibraries();
            const vulnerableLibraries = browserService.getVulnerableLibraries();
            for (const lib of vulnerableLibraries) await persistenceService.log('vuln_library', lib);

            // Step 6: Security Assessment
            const securityAssessment = new SecurityAssessment();
            const page = browserService.getPage();
            let securityResult = null;
            if (page) {
                securityResult = await securityAssessment.assess(page, targetUrl, visitedUrls);
                securityCritical = (securityResult.summary.critical || 0) + (securityResult.summary.high || 0);

                if (securityResult.findings) {
                    for (const finding of securityResult.findings) {
                        await persistenceService.log('security_assessment', finding);
                    }
                }
            }

            // Step 7: Report Generation
            const report = {
                meta: {
                    version: '1.0.0',
                    generatedAt: new Date().toISOString(),
                    targetUrl: targetUrl,
                    duration: Date.now() - startTime,
                },
                authentication: { success: true, duration: 0 }, // Simplified for runner
                crawl: crawlResult,
                integrity: integrityResult,
                network_incidents: browserService.getNetworkIncidents(),
                leaked_secrets: browserService.getLeakedSecrets(),
                supabase_issues: supabaseIssues,
                vulnerable_libraries: vulnerableLibraries,
                security_assessment: securityResult,
                lighthouse: auditResult.lighthouse,
                security_alerts: auditResult.security_alerts,
                ignored_alerts: auditResult.ignored_alerts || [],
                summary: {
                    ...auditResult.summary,
                    crawlPagesInvalid: crawlResult.failedPages,
                    crawlPagesSuspicious: crawlResult.suspiciousPages,
                    integrityFailures: integrityResult.failed,
                    securityCritical: securityResult?.summary.critical || 0,
                    securityHigh: securityResult?.summary.high || 0,
                    supabaseIssues: supabaseIssues.length,
                    vulnerableLibraries: vulnerableLibraries.length,
                },
            };

            // Calculate Health Score (simplified logic)
            healthScore = Math.round(
                (report.summary.performanceScore +
                    report.summary.accessibilityScore +
                    report.summary.seoScore) / 3
            );

            if (securityCritical > 0 || report.summary.highRiskAlerts > 0) {
                healthScore = Math.max(0, healthScore - 20);
                finalStatus = 'fail';
            } else if (healthScore >= 90) {
                finalStatus = 'pass';
            } else {
                finalStatus = 'warning';
            }

            // Save Reports
            const domain = new URL(targetUrl).hostname;
            const domainReportDir = path.join(this.config.REPORTS_DIR, domain);

            if (!fs.existsSync(domainReportDir)) {
                fs.mkdirSync(domainReportDir, { recursive: true });
            }

            // Hack: Subclass check or modify HtmlReportGenerator to accept output dir per run? 
            // HtmlReportGenerator takes reportsDir in constructor.
            // We instantiated it with default. Let's make sure it saves nicely or we rename.
            // Actually HtmlReportGenerator generates output based on domain. 
            // Let's use it as is, but we might want to organize them into folders.

            htmlReportPath = await htmlReportGenerator.generate(report as any);
            const pdfReportPath = htmlReportPath.replace('.html', '.pdf');
            await htmlReportGenerator.generatePdf(htmlReportPath, pdfReportPath);

            // SIEM Integration: Forward Critical/High Security Findings
            if (this.config.siem?.enabled) {
                // 1. Black Box Security Findings
                if (securityResult && securityResult.findings) {
                    for (const finding of securityResult.findings) {
                        if (['critical', 'high'].includes(finding.severity.toLowerCase())) {
                            await SiemLogger.logVulnerability({
                                id: finding.id,
                                severity: finding.severity,
                                description: finding.description,
                                targetUrl: finding.endpoint || targetUrl,
                                complianceTags: [] // Will be enriched by logger if empty
                            });
                        }
                    }
                }

                // 2. ZAP / Audit Alerts
                if (auditResult.security_alerts) {
                    for (const alert of auditResult.security_alerts) {
                        const risk = alert.risk ? alert.risk.toLowerCase() : 'low';
                        if (['critical', 'high'].includes(risk)) {
                            await SiemLogger.logVulnerability({
                                id: alert.alert ? alert.alert.toLowerCase().replace(/\s+/g, '-') : 'zap-alert',
                                severity: risk,
                                description: alert.description,
                                targetUrl: targetUrl,
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
                criticalIssues: securityCritical + report.summary.highRiskAlerts,
                status: finalStatus
            };

        } catch (error) {
            logFailure(`Scan failed for ${targetUrl}: ${error}`);
            return {
                url: targetUrl,
                domain: targetUrl,
                healthScore: 0,
                reportPath: '#',
                criticalIssues: 0,
                status: 'fail'
            };
        } finally {
            await browserService.close();
            await auditService.cleanup();
        }
    }
}
