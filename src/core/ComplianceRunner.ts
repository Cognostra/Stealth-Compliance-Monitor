/**
 * Compliance Runner
 * Main orchestrator for the Live-Site Compliance Monitor
 */

import * as fs from 'fs';
import * as path from 'path';
import { BrowserService } from '../services/BrowserService';
import { LighthouseService } from '../services/LighthouseService';
import { ZapService } from '../services/ZapService';
import { UserFlowRunner, DEFAULT_FLOWS } from './UserFlowRunner';
import { ComplianceConfig } from '../config/compliance.config';
import { logger, logSection, logStep, logSuccess, logFailure, logWarning } from '../utils/logger';
import {
    AuditReport,
    PerformanceMetrics,
    AccessibilityMetrics,
    SecurityMetrics,
    SecurityHeader,
    UserFlowResult,
} from '../types';

/**
 * Score thresholds for pass/fail
 */
const THRESHOLDS = {
    performance: 50,
    accessibility: 70,
    security: 70,
};

/**
 * Required security headers to check
 */
const REQUIRED_HEADERS: { name: string; recommendation: string }[] = [
    { name: 'strict-transport-security', recommendation: 'Add HSTS header with max-age of at least 31536000' },
    { name: 'content-security-policy', recommendation: 'Implement a strict CSP to prevent XSS attacks' },
    { name: 'x-content-type-options', recommendation: 'Set to "nosniff" to prevent MIME-type sniffing' },
    { name: 'x-frame-options', recommendation: 'Set to "DENY" or "SAMEORIGIN" to prevent clickjacking' },
    { name: 'x-xss-protection', recommendation: 'Set to "1; mode=block" (legacy but still useful)' },
    { name: 'referrer-policy', recommendation: 'Set to "strict-origin-when-cross-origin" or stricter' },
    { name: 'permissions-policy', recommendation: 'Restrict browser features not needed by your app' },
];

export class ComplianceRunner {
    private config: ComplianceConfig;
    private browserService: BrowserService;
    private lighthouseService: LighthouseService;
    private zapService: ZapService;
    private userFlowRunner: UserFlowRunner | null = null;

    constructor(config: ComplianceConfig) {
        this.config = config;
        this.browserService = new BrowserService();
        this.lighthouseService = new LighthouseService(logger);
        this.zapService = new ZapService(this.config, logger);
    }

    /**
     * Initialize all services
     */
    async initialize(): Promise<void> {
        logSection('LSCM Initialization');

        logger.info(`Target URL: ${this.config.LIVE_URL}`);

        // Initialize services
        logStep(1, 3, 'Initializing browser...');
        await this.browserService.initialize();

        logStep(2, 3, 'Initializing ZAP (passive mode)...');
        await this.zapService.initialize();

        logStep(3, 3, 'Setting up user flow runner...');
        this.userFlowRunner = new UserFlowRunner(
            this.browserService,
            this.config.LIVE_URL,
            {
                email: this.config.TEST_EMAIL,
                password: this.config.TEST_PASSWORD,
            },
            logger
        );

        logSuccess('All services initialized');
    }

    /**
     * Run full compliance audit
     */
    async runAudit(): Promise<AuditReport> {
        const startTime = Date.now();

        logSection('Starting Compliance Audit');
        logger.info(`Target: ${this.config.LIVE_URL}`);
        logger.info(`Timestamp: ${new Date().toISOString()}`);

        // 1. Run User Flows
        logSection('User Flow Verification');
        const userFlows = await this.runUserFlows();

        // 2. Run Lighthouse Audit
        logSection('Performance & Accessibility Audit');
        const { performance, accessibility } = await this.runLighthouseAudit();

        // 3. Run Security Checks
        logSection('Security Header Analysis');
        const security = await this.runSecurityAudit();

        // 4. Calculate overall score
        const overallScore = this.calculateOverallScore(performance, accessibility, security);
        const passed = this.checkPassCriteria(performance, accessibility, security, userFlows);

        // 5. Generate report
        const report: AuditReport = {
            timestamp: new Date().toISOString(),
            targetUrl: this.config.LIVE_URL,
            duration: Date.now() - startTime,
            performance,
            accessibility,
            security,
            userFlows,
            overallScore,
            passed,
        };

        // 6. Save report
        await this.saveReport(report);

        // 7. Print summary
        this.printSummary(report);

        return report;
    }

    /**
     * Run user flow tests
     */
    private async runUserFlows(): Promise<UserFlowResult[]> {
        if (!this.userFlowRunner) {
            throw new Error('User flow runner not initialized');
        }

        return this.userFlowRunner.runAllFlows(DEFAULT_FLOWS);
    }

    /**
     * Run Lighthouse performance and accessibility audit
     */
    private async runLighthouseAudit(): Promise<{
        performance: PerformanceMetrics;
        accessibility: AccessibilityMetrics;
    }> {
        try {
            return await this.lighthouseService.runAudit(this.config.LIVE_URL);
        } catch (error) {
            logger.error('Lighthouse audit failed', { error });
            return {
                performance: this.getDefaultPerformanceMetrics(),
                accessibility: this.getDefaultAccessibilityMetrics(),
            };
        }
    }

    /**
     * Run security header and ZAP passive checks
     */
    private async runSecurityAudit(): Promise<SecurityMetrics> {
        // Navigate to capture headers
        await this.browserService.goto(this.config.LIVE_URL);

        // Get security headers from browser
        const responseHeaders = this.browserService.getLastResponseHeaders();
        const headers = this.analyzeSecurityHeaders(responseHeaders);

        const presentHeaders = headers.filter(h => h.present).length;
        const headerScore = Math.round((presentHeaders / headers.length) * 100);

        // Log header results
        headers.forEach(header => {
            if (header.present) {
                logSuccess(`${header.name}: ${header.value?.substring(0, 50)}...`);
            } else {
                logWarning(`${header.name}: MISSING - ${header.recommendation}`);
            }
        });

        // Get ZAP alerts (passive only)
        const alerts = await this.zapService.getAlerts(this.config.LIVE_URL);

        // Calculate security score (headers + ZAP findings)
        const highAlerts = alerts.filter(a => a.risk === 'High').length;
        const mediumAlerts = alerts.filter(a => a.risk === 'Medium').length;
        const alertPenalty = (highAlerts * 20) + (mediumAlerts * 10);
        const securityScore = Math.max(0, headerScore - alertPenalty);

        return {
            score: securityScore,
            headers,
            alerts,
            passiveOnly: true,
        };
    }

    /**
     * Analyze security headers from response
     */
    private analyzeSecurityHeaders(responseHeaders: Map<string, string>): SecurityHeader[] {
        return REQUIRED_HEADERS.map(header => {
            const headerValue = responseHeaders.get(header.name);
            return {
                name: header.name,
                present: !!headerValue,
                value: headerValue,
                recommendation: headerValue ? undefined : header.recommendation,
            };
        });
    }

    /**
     * Calculate overall compliance score
     */
    private calculateOverallScore(
        performance: PerformanceMetrics,
        accessibility: AccessibilityMetrics,
        security: SecurityMetrics
    ): number {
        return Math.round(
            performance.score * 0.3 +
            accessibility.score * 0.3 +
            security.score * 0.4
        );
    }

    /**
     * Check if audit passes all criteria
     */
    private checkPassCriteria(
        performance: PerformanceMetrics,
        accessibility: AccessibilityMetrics,
        security: SecurityMetrics,
        userFlows: UserFlowResult[]
    ): boolean {
        const performancePassed = performance.score >= THRESHOLDS.performance;
        const accessibilityPassed = accessibility.score >= THRESHOLDS.accessibility;
        const securityPassed = security.score >= THRESHOLDS.security;
        const flowsPassed = userFlows.every(f => f.passed);

        return performancePassed && accessibilityPassed && securityPassed && flowsPassed;
    }

    /**
     * Save audit report to file
     */
    private async saveReport(report: AuditReport): Promise<void> {
        const reportsDir = path.resolve(this.config.REPORTS_DIR);

        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        // Save detailed report
        const reportPath = path.join(reportsDir, 'audit_report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        logger.info(`Report saved: ${reportPath}`);

        // Also save to root for easy access
        const rootReportPath = path.resolve('audit_report.json');
        fs.writeFileSync(rootReportPath, JSON.stringify(report, null, 2));
    }

    /**
     * Print audit summary
     */
    private printSummary(report: AuditReport): void {
        logSection('Audit Summary');

        logger.info(`Target URL: ${report.targetUrl}`);
        logger.info(`Duration: ${(report.duration / 1000).toFixed(2)}s`);
        logger.info('');

        logger.info('Scores:');
        logger.info(`  Performance:    ${report.performance.score}/100 ${report.performance.score >= THRESHOLDS.performance ? '✓' : '✗'}`);
        logger.info(`  Accessibility:  ${report.accessibility.score}/100 ${report.accessibility.score >= THRESHOLDS.accessibility ? '✓' : '✗'}`);
        logger.info(`  Security:       ${report.security.score}/100 ${report.security.score >= THRESHOLDS.security ? '✓' : '✗'}`);
        logger.info('');
        logger.info(`  Overall Score:  ${report.overallScore}/100`);
        logger.info('');

        logger.info('User Flows:');
        report.userFlows.forEach(flow => {
            const status = flow.passed ? '✓ PASS' : '✗ FAIL';
            logger.info(`  ${flow.name}: ${status} (${flow.duration}ms)`);
        });
        logger.info('');

        if (report.passed) {
            logSuccess('AUDIT PASSED - All criteria met');
        } else {
            logFailure('AUDIT FAILED - Some criteria not met');
        }
    }

    /**
     * Default performance metrics when Lighthouse fails
     */
    private getDefaultPerformanceMetrics(): PerformanceMetrics {
        return {
            score: 0,
            firstContentfulPaint: 0,
            largestContentfulPaint: 0,
            totalBlockingTime: 0,
            cumulativeLayoutShift: 0,
            speedIndex: 0,
            timeToInteractive: 0,
        };
    }

    /**
     * Default accessibility metrics when Lighthouse fails
     */
    private getDefaultAccessibilityMetrics(): AccessibilityMetrics {
        return {
            score: 0,
            issues: [],
        };
    }

    /**
     * Cleanup all services
     */
    async cleanup(): Promise<void> {
        logSection('Cleanup');

        await this.browserService.close();
        await this.zapService.close();

        logSuccess('All services closed');
    }
}

export default ComplianceRunner;
