/**
 * HtmlReportGenerator Service - Engineer's Remediation Dashboard
 *
 * Generates a self-contained, offline-capable HTML remediation dashboard
 * with data enrichment, Playwright locators, and actionable fix guidance.
 * 
 * Supports:
 * - Standard in-memory report generation
 * - WAL (Write-Ahead Log) file recovery for crash resilience
 * - Custom branding and white-label options
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { logger } from '../utils/logger.js';
import { chromium } from 'playwright';
import { PersistenceService, HydratedSession } from './PersistenceService.js';
import { AiRemediationService } from './AiRemediationService.js';
import { HistoryService, RunSummary } from './HistoryService.js';
import { getComplianceTags } from '../data/compliance-map.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Branding configuration for white-label reports
 */
export interface BrandingConfig {
    /** Company/organization name */
    companyName: string;
    /** URL to logo image (PNG/SVG recommended) */
    logoUrl?: string;
    /** Primary brand color (hex format) */
    primaryColor: string;
    /** URL to external CSS file */
    customCssUrl?: string;
    /** Custom footer text */
    footerText?: string;
    /** Report title prefix */
    reportTitle?: string;
}

interface LighthouseMetrics {
    firstContentfulPaint: number;
    largestContentfulPaint: number;
    totalBlockingTime: number;
    cumulativeLayoutShift: number;
    speedIndex: number;
    timeToInteractive: number;
}

/**
 * Report data structure (matches the output from index.ts)
 */
interface ReportData {
    meta: {
        version: string;
        generatedAt: string;
        targetUrl: string;
        duration: number;
        runId?: string;
        profile?: string;
        gitSha?: string;
        runTag?: string;
        activeScanning?: boolean;
        viewport?: { width: number; height: number };
        browserEngine?: string;
        deviceScaleFactor?: number;
    };
    authentication: {
        success: boolean;
        duration: number;
    };
    crawl: {
        pagesVisited: number;
        failedPages: number;
        suspiciousPages: number;
        totalConsoleErrors: number;
        pageResults: Array<{
            url: string;
            status: number;
            title: string;
            contentValid: boolean;
            assetResult?: {
                brokenImages: string[];
                totalImages: number;
            };
            linkCheckResult?: {
                brokenLinks: Array<{ url: string; status: number; error?: string }>;
                totalChecked: number;
            };
            a11yResult?: {
                score: number;
                violations: Array<{
                    id: string;
                    impact: string;
                    description: string;
                    nodes: number;
                    target?: string[];
                }>;
            };
        }>;
    };
    integrity: {
        testsRun: number;
        passed: number;
        failed: number;
        results: Array<{
            url: string;
            passed: boolean;
            checkType: string;
            details: string;
        }>;
    };
    network_incidents: Array<{
        url: string;
        type: string;
        status: number;
    }>;
    leaked_secrets: Array<{
        type: string;
        fileUrl: string;
        maskedValue: string;
        risk: string;
    }>;
    lighthouse: {
        scores: {
            performance: number;
            accessibility: number;
            seo: number;
            bestPractices: number;
        };
        metrics: LighthouseMetrics;
    } | null;
    security_alerts: Array<{
        name: string;
        risk: string;
        description: string;
        url: string;
    }>;
    supabase_issues?: Array<{
        type: string;
        severity: string;
        description: string;
        evidence: string;
        remediation: string;
    }>;
    vulnerable_libraries?: Array<{
        name: string;
        version: string;
        severity: string;
        vulnerabilities: Array<{ cve: string; description: string }>;
        recommendation: string;
    }>;
    security_assessment?: {
        target: string;
        timestamp: string;
        duration: number;
        findings: Array<{
            id: string;
            category: string;
            severity: string;
            title: string;
            description: string;
            evidence: string;
            endpoint: string;
            remediation: string;
            cweId?: string;
            owaspCategory?: string;
        }>;
        summary: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
            totalTests: number;
        };
        reconnaissance: {
            endpoints: Array<{ url: string; method: string; type: string; requiresAuth: boolean }>;
            authMechanism: string;
            techStack: string[];
            cookies: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string }>;
        };
    } | null;
    active_scan?: {
        enabled: boolean;
        spiderUrls: string[];
        passiveAlerts: Array<{ name: string; risk: string; description: string; url: string; }>;
        activeAlerts: Array<{ name: string; risk: string; description: string; url: string; }>;
        duration: number;
        completed: boolean;
    } | null;
    custom_checks?: Array<{
        name: string;
        passed: boolean;
        violations: Array<{
            id: string;
            title: string;
            severity: string;
            description: string;
            url?: string;
            remediation?: string;
            evidence?: string;
            selector?: string;
        }>;
    }>;
    coverage?: Array<{
        name: string;
        status: 'ran' | 'skipped' | 'failed';
        detail?: string;
    }>;
    multi_device?: Array<{
        device: string;
        lighthouse: {
            scores: {
                performance: number;
                accessibility: number;
                seo: number;
                bestPractices: number;
            };
            metrics: LighthouseMetrics;
        } | null;
        crawlSummary: {
            pagesVisited: number;
            failedPages: number;
        };
        screenshotPath?: string;
    }>;
    vuln_intelligence?: {
        enabled: boolean;
        enrichedLibraries: Array<{
            cveId: string;
            cveDescription?: string;
            cwe?: { id: string; name: string; description: string };
            cvss: { version: string; baseScore: number; severity: string; vector: string };
            exploit: { available: boolean; source?: string; maturity?: string };
            knownExploitedVuln: boolean;
            remediation: { type: string; description: string; targetVersion?: string; effort: string; priority: number };
            riskScore: number;
            riskFactors: string[];
        }>;
        enrichedAlerts: Array<{
            cveId: string;
            cveDescription?: string;
            cwe?: { id: string; name: string; description: string };
            cvss: { version: string; baseScore: number; severity: string; vector: string };
            exploit: { available: boolean; source?: string; maturity?: string };
            knownExploitedVuln: boolean;
            remediation: { type: string; description: string; targetVersion?: string; effort: string; priority: number };
            riskScore: number;
            riskFactors: string[];
        }>;
        summary: {
            totalFindings: number;
            bySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; NONE: number };
            withExploits: number;
            inKev: number;
            averageRiskScore: number;
            topCves: Array<{ cveId: string; riskScore: number }>;
        };
    } | null;
    summary: {
        performanceScore: number;
        accessibilityScore: number;
        seoScore: number;
        highRiskAlerts: number;
        mediumRiskAlerts: number;
        passedAudit: boolean;
        securityCritical?: number;
        securityHigh?: number;
        supabaseIssues?: number;
        vulnerableLibraries?: number;
        activeAlerts?: number;
        customViolations?: number;
        crawlPagesInvalid: number;
        crawlPagesSuspicious: number;
        integrityFailures: number;
    };
}

/**
 * Enriched issue object with remediation data
 */
/**
 * Issue Categories
 */
export type IssueCategory = 'accessibility' | 'performance' | 'security' | 'assets' | 'integrity' | 'pentest' | 'supabase' | 'dependencies';

/**
 * Issue Severity Levels
 */
export type IssueSeverity = 'critical' | 'serious' | 'warning' | 'info';

/**
 * Remediation Effort Levels
 */
export type IssueEffort = 'low' | 'medium' | 'high';

/**
 * Enriched issue object with remediation data
 */
interface ArchitectIssue {
    id: string;
    category: IssueCategory;
    severity: IssueSeverity;
    effort: IssueEffort;
    component: string;
    playwrightLocator: string;
    issue: string;
    remediation: string;
    docsUrl: string;
    nodeCount?: number;

    url?: string;
    aiSolution?: string;
    complianceTags?: string[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// REMEDIATION KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════════════════════

const REMEDIATION_DATABASE: Record<string, {
    remediation: string;
    effort: 'low' | 'medium' | 'high';
    docsUrl: string;
}> = {
    // Accessibility Issues
    'button-name': {
        remediation: 'Add aria-label or visible text content to button elements. For icon buttons: <button aria-label="Delete item"><Icon /></button>',
        effort: 'low',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/button-name'
    },
    'color-contrast': {
        remediation: 'Adjust foreground/background colors to meet WCAG AA ratio (4.5:1 for normal text, 3:1 for large text). Use browser DevTools color picker to verify.',
        effort: 'low',
        docsUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html'
    },
    'image-alt': {
        remediation: 'Add descriptive alt attribute to <img> elements. For decorative images use alt="".',
        effort: 'low',
        docsUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/non-text-content.html'
    },
    'link-name': {
        remediation: 'Add accessible text to links via visible content, aria-label, or aria-labelledby.',
        effort: 'low',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/link-name'
    },
    'label': {
        remediation: 'Associate form inputs with <label> elements using for/id attributes or wrapping.',
        effort: 'low',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/label'
    },
    'heading-order': {
        remediation: 'Ensure heading levels increase sequentially (h1 -> h2 -> h3). Do not skip levels.',
        effort: 'medium',
        docsUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/info-and-relationships.html'
    },
    'landmark-one-main': {
        remediation: 'Add a single <main> landmark element to contain the primary page content.',
        effort: 'low',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/landmark-one-main'
    },
    'region': {
        remediation: 'Wrap page content in landmark elements (<header>, <nav>, <main>, <footer>).',
        effort: 'medium',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/region'
    },
    'duplicate-id': {
        remediation: 'Ensure all id attributes are unique within the document.',
        effort: 'low',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/duplicate-id'
    },
    'aria-hidden-focus': {
        remediation: 'Remove focusable elements from aria-hidden containers or remove aria-hidden.',
        effort: 'medium',
        docsUrl: 'https://dequeuniversity.com/rules/axe/4.7/aria-hidden-focus'
    },
    'tabindex': {
        remediation: 'Avoid positive tabindex values. Use tabindex="0" for focusable custom elements.',
        effort: 'low',
        docsUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/tabindex'
    },
    'focus-visible': {
        remediation: 'Ensure :focus styles are visible. Do not use outline:none without a replacement.',
        effort: 'low',
        docsUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/focus-visible.html'
    },

    // Performance Issues
    'largest-contentful-paint': {
        remediation: 'Optimize LCP by: preloading hero images, using next/image, reducing server response time, removing render-blocking resources.',
        effort: 'high',
        docsUrl: 'https://web.dev/lcp/'
    },
    'cumulative-layout-shift': {
        remediation: 'Reserve space for images/ads with width/height attributes. Avoid inserting content above existing content.',
        effort: 'medium',
        docsUrl: 'https://web.dev/cls/'
    },
    'total-blocking-time': {
        remediation: 'Break up long tasks, defer non-critical JavaScript, use web workers for heavy computation.',
        effort: 'high',
        docsUrl: 'https://web.dev/tbt/'
    },
    'first-contentful-paint': {
        remediation: 'Reduce server response time, eliminate render-blocking resources, inline critical CSS.',
        effort: 'medium',
        docsUrl: 'https://web.dev/fcp/'
    },

    // Security Issues
    'leaked-api-key': {
        remediation: 'CRITICAL: Rotate the exposed key immediately. Move to server-side environment variables. Never commit secrets to version control.',
        effort: 'high',
        docsUrl: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials'
    },
    'leaked-jwt': {
        remediation: 'Revoke the token if possible. Implement proper token storage (httpOnly cookies) and short expiry times.',
        effort: 'medium',
        docsUrl: 'https://owasp.org/www-project-web-security-testing-guide/'
    },
    'missing-csp': {
        remediation: 'Implement Content-Security-Policy header to prevent XSS attacks.',
        effort: 'medium',
        docsUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
    },
    'missing-hsts': {
        remediation: 'Add Strict-Transport-Security header with max-age of at least 1 year.',
        effort: 'low',
        docsUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
    },

    // Asset Issues
    'broken-image': {
        remediation: 'Verify image URL exists. Implement fallback images with onError handler. Check blob storage retention policies.',
        effort: 'medium',
        docsUrl: 'https://nextjs.org/docs/pages/api-reference/components/image'
    },
    'broken-link': {
        remediation: 'Verify linked resource exists. Implement 404 handling. Add link validation to CI pipeline.',
        effort: 'medium',
        docsUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404'
    }
};

// Default remediation for unknown issues
const DEFAULT_REMEDIATION = {
    remediation: 'Investigate the specific error and apply appropriate fix based on context.',
    effort: 'medium' as const,
    docsUrl: 'https://developer.mozilla.org/en-US/docs/Web'
};

// Default branding configuration
const DEFAULT_BRANDING: BrandingConfig = {
    companyName: 'Stealth Compliance Monitor',
    primaryColor: '#3fb950',
    logoUrl: undefined,
    customCssUrl: undefined,
    footerText: undefined,
    reportTitle: undefined,
};

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class HtmlReportGenerator {
    private readonly reportsDir: string;
    private readonly aiService: AiRemediationService;
    private readonly historyService: HistoryService;
    private branding: BrandingConfig;

    constructor(reportsDir: string = './reports', branding?: Partial<BrandingConfig>) {
        this.reportsDir = reportsDir;
        this.aiService = new AiRemediationService();
        this.historyService = new HistoryService();
        this.branding = { ...DEFAULT_BRANDING, ...branding };
    }

    /**
     * Update branding configuration after construction
     */
    public setBranding(branding: Partial<BrandingConfig>): void {
        this.branding = { ...this.branding, ...branding };
    }

    /**
     * Extract domain name from URL for filename
     * Example: https://app.loadout.com/dashboard -> loadout
     */
    private extractDomainName(url: string): string {
        try {
            const parsed = new URL(url);
            let hostname = parsed.hostname;

            // Remove www. prefix
            hostname = hostname.replace(/^www\./, '');

            // Extract the main domain (handle subdomains like app.loadout.com)
            const parts = hostname.split('.');
            if (parts.length >= 2) {
                // Get second-to-last part (e.g., 'loadout' from 'app.loadout.com')
                return parts[parts.length - 2];
            }
            return parts[0];
        } catch {
            // Fallback if URL parsing fails
            return 'audit';
        }
    }

    /**
     * Generate the output filename based on target URL
     */
    private getOutputFilename(targetUrl: string): string {
        const domain = this.extractDomainName(targetUrl);
        return `${domain}-audit-report.html`;
    }

    /**
     * Calculate overall health score (0-100)
     */
    private calculateHealthScore(report: ReportData, issues: ArchitectIssue[]): number {
        let score = 100;

        // Deduct for issues by severity
        const criticalCount = issues.filter(i => i.severity === 'critical').length;
        const seriousCount = issues.filter(i => i.severity === 'serious').length;
        const warningCount = issues.filter(i => i.severity === 'warning').length;

        score -= criticalCount * 15;
        score -= seriousCount * 8;
        score -= warningCount * 3;

        // Factor in Lighthouse scores if available
        if (report.lighthouse) {
            const avgLighthouse = (
                report.summary.performanceScore +
                report.summary.accessibilityScore +
                report.summary.seoScore
            ) / 3;
            score = Math.round((score + avgLighthouse) / 2);
        }

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Identify top 3 quick wins (high impact, low effort)
     */
    private identifyQuickWins(issues: ArchitectIssue[]): ArchitectIssue[] {
        // Sort by: low effort first, then by severity (critical > serious > warning)
        const severityOrder = { critical: 0, serious: 1, warning: 2, info: 3 };
        const effortOrder = { low: 0, medium: 1, high: 2 };

        return [...issues]
            .sort((a, b) => {
                // First sort by effort (low first)
                const effortDiff = effortOrder[a.effort] - effortOrder[b.effort];
                if (effortDiff !== 0) return effortDiff;
                // Then by severity (critical first)
                return severityOrder[a.severity] - severityOrder[b.severity];
            })
            .slice(0, 3);
    }

    /**
     * Generate Playwright locator suggestion from element info
     */
    private generatePlaywrightLocator(issueId: string, target?: string[], nodeCount?: number): string {
        // If we have CSS selector targets from axe-core
        if (target && target.length > 0) {
            const selector = target[0];

            // Convert common patterns to Playwright locators
            if (selector.includes('button')) {
                return `page.getByRole('button')`;
            }
            if (selector.includes('input')) {
                return `page.getByRole('textbox')`;
            }
            if (selector.includes('img')) {
                return `page.getByRole('img')`;
            }
            if (selector.includes('a[')) {
                return `page.getByRole('link')`;
            }

            // Return as CSS selector
            return `page.locator('${selector}')`;
        }

        // Generate based on issue type
        switch (issueId) {
            case 'button-name':
                return `page.getByRole('button').filter({ hasNot: page.getByText(/./)} )`;
            case 'color-contrast':
                return `page.locator('[style*="color"]')`;
            case 'image-alt':
                return `page.getByRole('img').filter({ has: page.locator(':not([alt])') })`;
            case 'link-name':
                return `page.getByRole('link').filter({ hasNot: page.getByText(/./)} )`;
            case 'label':
                return `page.getByRole('textbox')`;
            default:
                return `page.locator('/* ${issueId} - ${nodeCount || 0} elements */');`;
        }
    }

    /**
     * Enrich raw report data into ArchitectIssue objects
     */
    private async enrichIssues(report: ReportData): Promise<ArchitectIssue[]> {
        const issues: ArchitectIssue[] = [];

        this.processAccessibilityViolations(report, issues);
        this.processSecurityAlerts(report, issues);
        this.processLeakedSecrets(report, issues);
        this.processBrokenAssets(report, issues);
        this.processLighthouseMetrics(report, issues);
        this.processIntegrityFailures(report, issues);
        this.processPentestFindings(report, issues);
        this.processSupabaseIssues(report, issues);
        this.processVulnerableLibraries(report, issues);
        this.processActiveScanAlerts(report, issues);
        this.processCustomChecks(report, issues);
        
        await this.applyAiRemediation(issues);
        
        return issues;
    }

    private processAccessibilityViolations(report: ReportData, issues: ArchitectIssue[]): void {
        const pageResults = report.crawl?.pageResults ?? [];
        pageResults.forEach(page => {
            page.a11yResult?.violations?.forEach(violation => {
                const remediation = REMEDIATION_DATABASE[violation.id] || DEFAULT_REMEDIATION;
                const severityMap: Record<string, IssueSeverity> = {
                    critical: 'critical',
                    serious: 'serious',
                    moderate: 'warning',
                    minor: 'info'
                };

                issues.push({
                    id: violation.id,
                    category: 'accessibility',
                    severity: severityMap[violation.impact] || 'warning',
                    effort: remediation.effort,
                    component: `${violation.nodes} element(s)`,
                    playwrightLocator: this.generatePlaywrightLocator(violation.id, violation.target, violation.nodes),
                    issue: violation.description,
                    remediation: remediation.remediation,
                    docsUrl: remediation.docsUrl,
                    nodeCount: violation.nodes,
                    url: page.url,
                    complianceTags: getComplianceTags(violation.id)
                });
            });
        });
    }

    private processSecurityAlerts(report: ReportData, issues: ArchitectIssue[]): void {
        (report.security_alerts ?? []).forEach(alert => {
            const riskMap: Record<string, IssueSeverity> = {
                High: 'critical',
                Medium: 'serious',
                Low: 'warning'
            };

            const alertId = alert.name.toLowerCase().replace(/\s+/g, '-');
            const remediation = REMEDIATION_DATABASE[alertId];

            issues.push({
                id: alertId,
                category: 'security',
                severity: riskMap[alert.risk] || 'warning',
                effort: 'medium',
                component: new URL(alert.url).pathname || '/',
                playwrightLocator: `await page.goto('${alert.url}')`,
                issue: alert.description,
                remediation: remediation?.remediation || 'Review security configuration and apply recommended headers.',
                docsUrl: remediation?.docsUrl || 'https://owasp.org/www-project-web-security-testing-guide/',
            });
        });
    }

    private processLeakedSecrets(report: ReportData, issues: ArchitectIssue[]): void {
        (report.leaked_secrets ?? []).forEach(secret => {
            issues.push({
                id: `leaked-${secret.type.toLowerCase().replace(/\s+/g, '-')}`,
                category: 'security',
                severity: 'critical',
                effort: 'high',
                component: secret.fileUrl,
                playwrightLocator: `await page.goto('${secret.fileUrl}')`,
                issue: `Exposed ${secret.type}: ${secret.maskedValue}`,
                remediation: REMEDIATION_DATABASE['leaked-api-key']?.remediation || 'Immediately rotate exposed credentials.',
                docsUrl: REMEDIATION_DATABASE['leaked-api-key']?.docsUrl || '',
                url: secret.fileUrl
            });
        });
    }

    private processBrokenAssets(report: ReportData, issues: ArchitectIssue[]): void {
        const pageResults = report.crawl?.pageResults ?? [];
        pageResults.forEach(page => {
            page.assetResult?.brokenImages?.forEach(imgUrl => {
                const remediation = REMEDIATION_DATABASE['broken-image'] || DEFAULT_REMEDIATION;
                issues.push({
                    id: 'broken-image',
                    category: 'assets',
                    severity: 'warning',
                    effort: remediation.effort,
                    component: imgUrl.substring(0, 80) + (imgUrl.length > 80 ? '...' : ''),
                    playwrightLocator: `page.locator('img[src*="${this.extractFilename(imgUrl)}"]')`,
                    issue: 'Image failed to load or returned error status',
                    remediation: remediation.remediation,
                    docsUrl: remediation.docsUrl,
                    url: page.url
                });
            });

            page.linkCheckResult?.brokenLinks?.forEach(link => {
                const remediation = REMEDIATION_DATABASE['broken-link'] || DEFAULT_REMEDIATION;
                issues.push({
                    id: 'broken-link',
                    category: 'assets',
                    severity: 'warning',
                    effort: remediation.effort,
                    component: link.url,
                    playwrightLocator: `page.locator('a[href="${link.url}"]')`,
                    issue: `Link returned ${link.status || 'error'}: ${link.error || 'Request failed'}`,
                    remediation: remediation.remediation,
                    docsUrl: remediation.docsUrl,
                    url: page.url
                });
            });
        });
    }

    private processLighthouseMetrics(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.lighthouse?.metrics) return;
        const { metrics } = report.lighthouse;

        if (metrics.largestContentfulPaint > 2500) {
            const remediation = REMEDIATION_DATABASE['largest-contentful-paint'];
            issues.push({
                id: 'largest-contentful-paint',
                category: 'performance',
                severity: metrics.largestContentfulPaint > 4000 ? 'critical' : 'serious',
                effort: remediation.effort,
                component: 'LCP Element',
                playwrightLocator: `// Identify LCP element with Lighthouse DevTools`,
                issue: `LCP is ${metrics.largestContentfulPaint}ms (target: <2500ms)`,
                remediation: remediation.remediation,
                docsUrl: remediation.docsUrl
            });
        }

        if (metrics.cumulativeLayoutShift > 0.1) {
            const remediation = REMEDIATION_DATABASE['cumulative-layout-shift'];
            issues.push({
                id: 'cumulative-layout-shift',
                category: 'performance',
                severity: metrics.cumulativeLayoutShift > 0.25 ? 'critical' : 'serious',
                effort: remediation.effort,
                component: 'Layout Shifting Elements',
                playwrightLocator: `// Use Chrome DevTools Performance panel to identify shifting elements`,
                issue: `CLS is ${metrics.cumulativeLayoutShift.toFixed(3)} (target: <0.1)`,
                remediation: remediation.remediation,
                docsUrl: remediation.docsUrl
            });
        }

        if (metrics.totalBlockingTime > 200) {
            const remediation = REMEDIATION_DATABASE['total-blocking-time'];
            issues.push({
                id: 'total-blocking-time',
                category: 'performance',
                severity: metrics.totalBlockingTime > 600 ? 'critical' : 'serious',
                effort: remediation.effort,
                component: 'Main Thread',
                playwrightLocator: `// Profile with Chrome DevTools Performance panel`,
                issue: `TBT is ${metrics.totalBlockingTime}ms (target: <200ms)`,
                remediation: remediation.remediation,
                docsUrl: remediation.docsUrl
            });
        }
    }

    private processIntegrityFailures(report: ReportData, issues: ArchitectIssue[]): void {
        const integrityResults = report.integrity?.results ?? [];
        integrityResults.filter(r => !r.passed).forEach(result => {
            issues.push({
                id: result.checkType.toLowerCase().replace(/\s+/g, '-'),
                category: 'integrity',
                severity: 'warning',
                effort: 'medium',
                component: result.checkType,
                playwrightLocator: `await page.goto('${result.url}')`,
                issue: result.details,
                remediation: 'Investigate data integrity issue and verify expected behavior.',
                docsUrl: 'https://developer.mozilla.org/en-US/docs/Web',
                url: result.url
            });
        });
    }

    private processPentestFindings(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.security_assessment?.findings) return;
        
        report.security_assessment.findings.forEach(finding => {
            const severityMap: Record<string, IssueSeverity> = {
                CRITICAL: 'critical',
                HIGH: 'serious',
                MEDIUM: 'warning',
                LOW: 'info',
                INFO: 'info'
            };

            const effortMap: Record<string, IssueEffort> = {
                idor: 'high',
                xss: 'medium',
                sqli: 'high',
                auth: 'high',
                'rate-limit': 'medium',
                'info-disclosure': 'low',
                csrf: 'medium'
            };

            const severityKey = String(finding.severity || '').toUpperCase();
            const categoryKey = String(finding.category || 'issue');
            const endpoint = String(finding.endpoint || '').trim();
            
            issues.push({
                id: finding.id || `pentest-${categoryKey.toLowerCase()}`,
                category: 'pentest',
                severity: severityMap[severityKey] || 'warning',
                effort: effortMap[categoryKey] || 'medium',
                component: endpoint || '/',
                playwrightLocator: endpoint ? `await page.goto('${endpoint}')` : `// Navigate to affected endpoint`,
                issue: `[${categoryKey.toUpperCase()}] ${finding.title || 'Finding'}: ${finding.description || ''}`,
                remediation: finding.remediation || 'Review finding details and remediate accordingly.',
                docsUrl: finding.cweId
                    ? `https://cwe.mitre.org/data/definitions/${String(finding.cweId).replace('CWE-', '')}.html`
                    : 'https://owasp.org/www-project-web-security-testing-guide/',
                url: endpoint || undefined
            });
        });
    }

    private processSupabaseIssues(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.supabase_issues) return;
        
        report.supabase_issues.forEach(issue => {
            const severityMap: Record<string, IssueSeverity> = {
                CRITICAL: 'critical',
                HIGH: 'serious',
                MEDIUM: 'warning',
                LOW: 'info',
                INFO: 'info'
            };

            issues.push({
                id: `supabase-${issue.type}`,
                category: 'supabase',
                severity: severityMap[issue.severity] || 'warning',
                effort: issue.type.includes('service_role') ? 'high' : 'medium',
                component: 'Supabase Configuration',
                playwrightLocator: `// Check browser DevTools Network tab for Supabase API calls`,
                issue: issue.description,
                remediation: issue.remediation,
                docsUrl: 'https://supabase.com/docs/guides/auth/row-level-security'
            });
        });
    }

    private processVulnerableLibraries(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.vulnerable_libraries) return;

        report.vulnerable_libraries.forEach(lib => {
            const severityMap: Record<string, IssueSeverity> = {
                CRITICAL: 'critical',
                HIGH: 'serious',
                MEDIUM: 'serious',
                LOW: 'warning'
            };

            const cveList = lib.vulnerabilities.map(v => v.cve).join(', ');

            issues.push({
                id: `vuln-${lib.name.toLowerCase()}`,
                category: 'dependencies',
                severity: severityMap[lib.severity] || 'warning',
                effort: 'medium',
                component: `${lib.name} v${lib.version}`,
                playwrightLocator: `// Check browser DevTools Sources tab for ${lib.name}`,
                issue: `Vulnerable version of ${lib.name} detected (${lib.version}). CVEs: ${cveList}`,
                remediation: lib.recommendation,
                docsUrl: lib.vulnerabilities[0]?.cve
                    ? `https://nvd.nist.gov/vuln/detail/${lib.vulnerabilities[0].cve}`
                    : 'https://owasp.org/www-project-dependency-check/'
            });
        });
    }

    private processActiveScanAlerts(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.active_scan?.activeAlerts) return;

        report.active_scan.activeAlerts.forEach(alert => {
            const riskMap: Record<string, IssueSeverity> = {
                High: 'critical',
                Medium: 'serious',
                Low: 'warning'
            };

            issues.push({
                id: `active-${alert.name.toLowerCase().replace(/\s+/g, '-')}`,
                category: 'security',
                severity: riskMap[alert.risk] || 'warning',
                effort: 'medium',
                component: new URL(alert.url).pathname || '/',
                playwrightLocator: `await page.goto('${alert.url}')`,
                issue: `[ACTIVE SCAN] ${alert.description}`,
                remediation: REMEDIATION_DATABASE[alert.name.toLowerCase().replace(/\s+/g, '-')]?.remediation ||
                    'Review security configuration and apply recommended headers.',
                docsUrl: REMEDIATION_DATABASE[alert.name.toLowerCase().replace(/\s+/g, '-')]?.docsUrl ||
                    'https://owasp.org/www-project-web-security-testing-guide/',
                url: alert.url,
                complianceTags: getComplianceTags(alert.name)
            });
        });
    }

    private processCustomChecks(report: ReportData, issues: ArchitectIssue[]): void {
        if (!report.custom_checks) return;

        report.custom_checks.forEach(check => {
            check.violations.forEach(v => {
                const severityMap: Record<string, IssueSeverity> = {
                    critical: 'critical',
                    high: 'serious',
                    medium: 'warning',
                    low: 'info',
                    info: 'info'
                };

                issues.push({
                    id: v.id,
                    category: 'integrity',
                    severity: severityMap[v.severity.toLowerCase()] || 'warning',
                    effort: 'medium',
                    component: check.name,
                    playwrightLocator: v.selector ? `page.locator('${v.selector}')` : '// Custom check violation',
                    issue: v.description + (v.evidence ? ` Evidence: ${v.evidence}` : ''),
                    remediation: v.remediation || 'Fix the custom check violation.',
                    url: v.url,
                    docsUrl: '#'
                });
            });
        });
    }

    private async applyAiRemediation(issues: ArchitectIssue[]): Promise<void> {
        logger.info('Applying AI remediation to critical issues...');
        const criticalIssues = issues.filter(i => i.severity === 'critical');

        await Promise.all(criticalIssues.map(async (issue) => {
            try {
                const response = await this.aiService.generateFix({
                    type: issue.category,
                    details: issue.issue,
                    severity: issue.severity,
                    context: `Component: ${issue.component}. Locator: ${issue.playwrightLocator}`
                });
                issue.aiSolution = response.code;
            } catch (err) {
                logger.warn(`Failed to generate AI fix for ${issue.id}: ${err}`);
            }
        }));
    }

    /**
     * Extract filename from URL
     */
    private extractFilename(url: string): string {
        try {
            const pathname = new URL(url, 'http://localhost').pathname;
            const parts = pathname.split('/');
            return parts[parts.length - 1] || pathname;
        } catch {
            return url.split('/').pop() || url;
        }
    }

    /**
     * Generate HTML dashboard from report data
     */
    async generate(report: ReportData): Promise<string> {
        // Save run to history before generating report
        this.saveToHistory(report);

        const enrichedIssues = await this.enrichIssues(report);
        const healthScore = this.calculateHealthScore(report, enrichedIssues);
        const quickWins = this.identifyQuickWins(enrichedIssues);
        const history = this.historyService.getTrendData();

        const html = this.buildHtml(report, enrichedIssues, healthScore, quickWins, history);

        // Ensure reports directory exists
        if (!fs.existsSync(this.reportsDir)) {
            fs.mkdirSync(this.reportsDir, { recursive: true });
        }

        // Dynamic filename based on target URL (unless explicitly provided)
        const filename = this.getOutputFilename(report.meta.targetUrl);
        const providedOutputPath = (report as { outputPath?: string }).outputPath;
        const outputPath = providedOutputPath
            ? path.resolve(providedOutputPath)
            : path.join(this.reportsDir, filename);
        const outputDir = path.dirname(outputPath);
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        await this.writeHtmlFile(outputPath, html);

        // Also write to dashboard.html for backward compatibility
        const dashboardPath = path.join(this.reportsDir, 'dashboard.html');
        await this.writeHtmlFile(dashboardPath, html);

        logger.info(`Remediation Dashboard generated: ${outputPath}`);
        logger.info(`Dashboard also available at: ${dashboardPath}`);
        return outputPath;
    }

    private async writeHtmlFile(outputPath: string, html: string): Promise<void> {
        const stream = fs.createWriteStream(outputPath, { encoding: 'utf-8' });
        const chunkSize = 64 * 1024;

        return new Promise((resolve, reject) => {
            stream.on('error', reject);
            stream.on('finish', resolve);

            const writeChunks = async () => {
                for (let i = 0; i < html.length; i += chunkSize) {
                    if (!stream.write(html.slice(i, i + chunkSize))) {
                        await new Promise<void>(drainResolve => stream.once('drain', drainResolve));
                    }
                }
                stream.end();
            };

            void writeChunks();
        });
    }

    /**
     * Generate HTML dashboard from a Write-Ahead Log file (for crash recovery)
     * @param walFilePath - Path to the .jsonl WAL file
     * @returns Path to the generated HTML file
     */
    async generateFromWal(walFilePath: string): Promise<string> {
        logger.info(`Generating report from WAL: ${walFilePath}`);

        // Hydrate session data from WAL
        const session = PersistenceService.hydrate(walFilePath);

        if (!session.metadata) {
            throw new Error('WAL file contains no session metadata');
        }

        // Convert hydrated session to ReportData format
        const report = this.hydratedSessionToReportData(session);

        // Generate using existing logic
        return this.generate(report);
    }

    /**
     * Convert a hydrated WAL session to ReportData format
     * Note: Uses Partial and adds defaults since WAL may not have all data
     */
    private hydratedSessionToReportData(session: HydratedSession): ReportData {
        type SecurityAssessmentData = NonNullable<ReportData['security_assessment']>;
        type SecurityFinding = SecurityAssessmentData['findings'][number];
        type WalPageResult = {
            duration?: number;
            contentValid?: boolean;
            validation?: { hasErrorIndicator?: boolean; hasStuckSpinner?: boolean };
        };

        const metadata = session.metadata!;
        const pageResults = session.pageResults as WalPageResult[];
        const securityFindings = session.securityFindings as SecurityFinding[];
        const networkIncidents = session.networkIncidents as ReportData['network_incidents'];
        const leakedSecrets = session.leakedSecrets as ReportData['leaked_secrets'];
        const supabaseIssues = session.supabaseIssues as ReportData['supabase_issues'];
        const vulnLibraries = session.vulnLibraries as ReportData['vulnerable_libraries'];

        // Calculate total duration from page results
        const totalDuration = pageResults.reduce((sum, p) => {
            return sum + (p.duration || 0);
        }, 0);

        const failedPages = pageResults.filter((p) => !p.contentValid).length;
        const suspiciousPages = pageResults.filter((p) =>
            p.validation?.hasErrorIndicator || p.validation?.hasStuckSpinner
        ).length;

        const report = {
            meta: {
                version: metadata.version || '1.0.0',
                generatedAt: new Date().toISOString(),
                targetUrl: metadata.startUrl,
                duration: totalDuration,
                recoveredFromWal: true,
                walFile: metadata.sessionId,
                wasComplete: session.isComplete,
            },
            authentication: {
                success: true, // Assume success if we have data
                duration: 0,
            },
            crawl: {
                pagesVisited: session.pageResults.length,
                failedPages,
                suspiciousPages,
                totalConsoleErrors: session.consoleErrors.length,
                pageResults: pageResults as unknown as ReportData['crawl']['pageResults'],
            },
            integrity: {
                testsRun: 0,
                passed: 0,
                failed: 0,
                results: [],
            },
            network_incidents: networkIncidents,
            leaked_secrets: leakedSecrets,
            lighthouse: {
                scores: { performance: 0, accessibility: 0, seo: 0, bestPractices: 0 },
                metrics: {
                    firstContentfulPaint: 0,
                    largestContentfulPaint: 0,
                    totalBlockingTime: 0,
                    cumulativeLayoutShift: 0,
                    speedIndex: 0,
                    timeToInteractive: 0,
                },
            },
            security_alerts: [],
            supabase_issues: supabaseIssues,
            vulnerable_libraries: vulnLibraries,
            security_assessment: session.securityFindings.length > 0 ? {
                target: metadata.startUrl,
                timestamp: metadata.startTime,
                duration: totalDuration,
                findings: securityFindings,
                summary: {
                    critical: securityFindings.filter((f) => f.severity === 'critical').length,
                    high: securityFindings.filter((f) => f.severity === 'high').length,
                    medium: securityFindings.filter((f) => f.severity === 'medium').length,
                    low: securityFindings.filter((f) => f.severity === 'low').length,
                    info: securityFindings.filter((f) => f.severity === 'info').length,
                    totalTests: securityFindings.length,
                },
                reconnaissance: {
                    endpoints: [],
                    authMechanism: 'unknown',
                    techStack: [],
                    cookies: [],
                },
            } : null,
            summary: {
                performanceScore: 0,
                accessibilityScore: 0,
                seoScore: 0,
                highRiskAlerts: securityFindings.filter((f) => f.severity === 'high').length,
                mediumRiskAlerts: securityFindings.filter((f) => f.severity === 'medium').length,
                passedAudit: failedPages === 0 && suspiciousPages === 0,
                securityCritical: securityFindings.filter((f) => f.severity === 'critical').length,
                securityHigh: securityFindings.filter((f) => f.severity === 'high').length,
                supabaseIssues: supabaseIssues?.length ?? 0,
                vulnerableLibraries: vulnLibraries?.length ?? 0,
                crawlPagesInvalid: failedPages,
                crawlPagesSuspicious: suspiciousPages,
                integrityFailures: 0,
            },
        } as ReportData;

        return report;
    }

    /**
     * Save current run data to history
     */
    private saveToHistory(report: ReportData): void {
        const issues = this.enrichIssuesSync(report);
        const healthScore = this.calculateHealthScore(report, issues);

        const summary: RunSummary = {
            timestamp: report.meta.generatedAt,
            targetUrl: report.meta.targetUrl,
            overallScore: healthScore,
            performanceScore: report.summary.performanceScore,
            accessibilityScore: report.summary.accessibilityScore,
            securityScore: this.calculateSecurityScore(report),
            metrics: {
                criticalIssues: issues.filter(i => i.severity === 'critical').length,
                highIssues: issues.filter(i => i.severity === 'serious').length,
                passed: report.summary.passedAudit,
                duration: report.meta.duration,
                pagesVisited: report.crawl?.pagesVisited ?? 0
            }
        };

        this.historyService.saveRun(summary);
    }

    /**
     * Synchronous version of enrichIssues (no AI) for history saving
     */
    private enrichIssuesSync(report: ReportData): ArchitectIssue[] {
        // Reuse main enrich logic logic but without AI
        // Since we can't easily extract the sync logic, we will do a simplified mapping
        // This is only for counting critical issues for history
        const issues: ArchitectIssue[] = [];

        // A11y (Iterate over crawl results)
        if (report.crawl?.pageResults) {
            report.crawl.pageResults.forEach(page => {
                if (page.a11yResult?.violations) {
                    page.a11yResult.violations.forEach(v => {
                        const severityMap: Record<string, 'critical' | 'serious' | 'warning' | 'info'> = {
                            critical: 'critical',
                            serious: 'serious',
                            moderate: 'warning',
                            minor: 'info'
                        };

                        issues.push({
                            id: v.id,
                            category: 'accessibility',
                            severity: severityMap[v.impact] || 'warning',
                            effort: 'low',
                            component: 'Accessibility',
                            playwrightLocator: 'N/A',
                            issue: v.description,
                            remediation: 'Fix accessibility issue',
                            docsUrl: ''
                        });
                    });
                }
            });
        }

        // Security
        if (report.security_alerts) {
            report.security_alerts.forEach(a => {
                issues.push({
                    id: 'security-zap',
                    category: 'security',
                    severity: a.risk === 'High' ? 'critical' : 'warning',
                    effort: 'medium',
                    component: 'Security',
                    playwrightLocator: 'N/A',
                    issue: a.name,
                    remediation: '',
                    docsUrl: ''
                });
            });
        }

        return issues;
    }

    private calculateSecurityScore(report: ReportData): number {
        const summary = report.summary;
        const criticalFindings = summary.securityCritical || 0;
        const highFindings = summary.securityHigh || 0;
        const zapAlerts = summary.highRiskAlerts + summary.mediumRiskAlerts;

        return Math.max(0, Math.min(100,
            100 - (zapAlerts * 15) - (criticalFindings * 15) - (highFindings * 8)
        ));
    }

    /**
     * Build the complete HTML document
     */


    /**
     * Build header with health gauge
     */
    private buildHeader(report: ReportData, healthScore: number, domain: string): string {
        const gaugeColor = healthScore >= 90 ? '#3fb950' :
            healthScore >= 70 ? '#d29922' : '#f85149';

        return `
        <header class="header">
            <div class="header-left">
                <h1>Remediation Dashboard</h1>
                <div class="meta-info">
                    <span class="domain">${domain}</span>
                    <a href="${this.escapeHtml(report.meta.targetUrl)}" class="target-url" target="_blank">
                        ${this.escapeHtml(report.meta.targetUrl)}
                    </a>
                    <span class="timestamp">${new Date(report.meta.generatedAt).toLocaleString()}</span>
                    ${report.active_scan?.enabled ?
                '<span class="active-scan-badge">⚠️ ACTIVE SCANNING ENABLED</span>' : ''}
                </div>
            </div>
            <div class="health-gauge">
                <svg viewBox="0 0 120 70" class="gauge-svg">
                    <path class="gauge-bg" d="M10,60 A50,50 0 0,1 110,60" />
                    <path class="gauge-fill" d="M10,60 A50,50 0 0,1 110,60"
                          stroke="${gaugeColor}"
                          stroke-dasharray="${healthScore * 1.57}, 157" />
                    <text x="60" y="55" class="gauge-value">${healthScore}</text>
                    <text x="60" y="68" class="gauge-label">Health Score</text>
                </svg>
            </div>
        </header>`;
    }

    /**
     * Build Playwright environment metadata bar
     */
    private buildEnvironmentBar(report: ReportData): string {
        const viewport = report.meta.viewport || { width: 1280, height: 720 };
        const viewportType = viewport.width <= 480 ? 'Mobile' :
            viewport.width <= 768 ? 'Tablet' : 'Desktop';
        const browser = report.meta.browserEngine || 'Chromium';
        const scale = report.meta.deviceScaleFactor || 1;

        return `
        <div class="env-bar">
            <div class="env-item">
                <span class="env-icon">📐</span>
                <span class="env-label">Viewport</span>
                <span class="env-value">${viewportType} (${viewport.width}x${viewport.height})</span>
            </div>
            <div class="env-item">
                <span class="env-icon">🌐</span>
                <span class="env-label">Browser</span>
                <span class="env-value">${browser}</span>
            </div>
            <div class="env-item">
                <span class="env-icon">🔍</span>
                <span class="env-label">Scale Factor</span>
                <span class="env-value">${scale}x</span>
            </div>
            <div class="env-item">
                <span class="env-icon">⏱️</span>
                <span class="env-label">Duration</span>
                <span class="env-value">${(report.meta.duration / 1000).toFixed(1)}s</span>
            </div>
        </div>`;
    }

    /**
     * Build Quick Wins card
     */
    private buildQuickWinsCard(quickWins: ArchitectIssue[]): string {
        if (quickWins.length === 0) {
            return `
            <div class="quick-wins-card success">
                <div class="quick-wins-header">
                    <h2>Quick Wins</h2>
                    <span class="badge badge-success">All Clear</span>
                </div>
                <p class="no-issues">No actionable issues found. Great job!</p>
            </div>`;
        }

        return `
        <div class="quick-wins-card">
            <div class="quick-wins-header">
                <h2>Quick Wins</h2>
                <span class="badge badge-info">High Impact, Low Effort</span>
            </div>
            <div class="quick-wins-list">
                ${quickWins.map((win, i) => `
                <div class="quick-win-item">
                    <span class="quick-win-number">${i + 1}</span>
                    <div class="quick-win-content">
                        <div class="quick-win-header">
                            <span class="severity-badge severity-${win.severity}">${win.severity}</span>
                            <code class="issue-id">${win.id}</code>
                            <span class="effort-badge effort-${win.effort}">${win.effort} effort</span>
                        </div>
                        <p class="quick-win-issue">${this.escapeHtml(win.issue)}</p>
                        <div class="quick-win-fix">
                            <strong>Fix:</strong> ${this.escapeHtml(win.remediation)}
                        </div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>`;
    }

    /**
     * Build score cards section
     */
    private buildScoreCards(report: ReportData): string {
        const { summary } = report;

        // Calculate security score based on pentest findings
        const criticalFindings = summary.securityCritical || 0;
        const highFindings = summary.securityHigh || 0;
        const zapAlerts = summary.highRiskAlerts + summary.mediumRiskAlerts;

        // Pentest score: 100 - (criticals * 20) - (highs * 10) - (mediums * 5)
        const pentestScore = Math.max(0, 100 - (criticalFindings * 20) - (highFindings * 10));

        // Overall security combines ZAP alerts + pentest
        const securityScore = Math.max(0, Math.min(100,
            100 - (zapAlerts * 15) - (criticalFindings * 15) - (highFindings * 8)
        ));

        return `
        <section class="score-section">
            <div class="score-grid">
                ${this.buildScoreCard('Performance', summary.performanceScore, 'performance')}
                ${this.buildScoreCard('Accessibility', summary.accessibilityScore, 'accessibility')}
                ${this.buildScoreCard('SEO', summary.seoScore, 'seo')}
                ${this.buildScoreCard('Security', securityScore, 'security')}
                ${this.buildScoreCard('Pentest', pentestScore, 'pentest')}
            </div>
            ${report.lighthouse ? this.buildMetricsBar(report.lighthouse.metrics) : ''}
        </section>`;
    }

    /**
     * Build individual score card
     */
    private buildScoreCard(label: string, score: number, _type: string): string {
        const scoreClass = score >= 90 ? 'good' : score >= 70 ? 'warning' : 'critical';
        return `
        <div class="score-card score-${scoreClass}">
            <div class="score-ring">
                <svg viewBox="0 0 36 36">
                    <path class="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
                    <path class="ring-fill" stroke-dasharray="${score}, 100"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
                </svg>
                <span class="score-number">${score}</span>
            </div>
            <span class="score-label">${label}</span>
        </div>`;
    }

    /**
     * Build Core Web Vitals metrics bar
     */
    private buildMetricsBar(metrics: NonNullable<ReportData['lighthouse']>['metrics']): string {
        const getMetricStatus = (value: number, good: number, poor: number) =>
            value <= good ? 'good' : value <= poor ? 'warning' : 'critical';

        return `
        <div class="metrics-bar">
            <div class="metric ${getMetricStatus(metrics.firstContentfulPaint, 1800, 3000)}">
                <span class="metric-value">${metrics.firstContentfulPaint}ms</span>
                <span class="metric-label">FCP</span>
            </div>
            <div class="metric ${getMetricStatus(metrics.largestContentfulPaint, 2500, 4000)}">
                <span class="metric-value">${metrics.largestContentfulPaint}ms</span>
                <span class="metric-label">LCP</span>
            </div>
            <div class="metric ${getMetricStatus(metrics.totalBlockingTime, 200, 600)}">
                <span class="metric-value">${metrics.totalBlockingTime}ms</span>
                <span class="metric-label">TBT</span>
            </div>
            <div class="metric ${getMetricStatus(metrics.cumulativeLayoutShift * 1000, 100, 250)}">
                <span class="metric-value">${metrics.cumulativeLayoutShift.toFixed(3)}</span>
                <span class="metric-label">CLS</span>
            </div>
            <div class="metric ${getMetricStatus(metrics.speedIndex, 3400, 5800)}">
                <span class="metric-value">${metrics.speedIndex}ms</span>
                <span class="metric-label">SI</span>
            </div>
            <div class="metric ${getMetricStatus(metrics.timeToInteractive, 3800, 7300)}">
                <span class="metric-value">${metrics.timeToInteractive}ms</span>
                <span class="metric-label">TTI</span>
            </div>
        </div>`;
    }

    /**
     * Build Security Assessment Summary section
     */
    private buildSecurityAssessmentSummary(report: ReportData): string {
        const assessment = report.security_assessment;
        const supabaseIssues = report.supabase_issues || [];
        const vulnLibs = report.vulnerable_libraries || [];

        if (!assessment && supabaseIssues.length === 0 && vulnLibs.length === 0) {
            return '';
        }

        const techStack = assessment?.reconnaissance.techStack || [];
        const authMechanism = assessment?.reconnaissance.authMechanism || 'Unknown';
        const endpointCount = assessment?.reconnaissance.endpoints.length || 0;
        const cookieCount = assessment?.reconnaissance.cookies.length || 0;
        const findings = assessment?.findings || [];

        const categoryIcons: Record<string, string> = {
            'sqli': '💉',
            'xss': '🔴',
            'idor': '🔓',
            'auth': '🔐',
            'rate-limit': '⏱️',
            'info-disclosure': '📤',
            'csrf': '🎭'
        };

        return `
        <section class="security-assessment-section">
            <div class="section-header">
                <h2>🔒 Security Assessment (Black-Box Pentest)</h2>
                <span class="badge ${assessment && (assessment.summary.critical > 0 || assessment.summary.high > 0) ? 'badge-critical' : 'badge-success'}">
                    ${assessment ? `${assessment.summary.totalTests} tests | ${findings.length} findings` : 'Passive Scans Only'}
                </span>
            </div>
            
            ${assessment ? `
            <div class="recon-grid">
                <div class="recon-card">
                    <h3>📡 Reconnaissance</h3>
                    <div class="recon-stats">
                        <div class="recon-stat">
                            <span class="recon-value">${endpointCount}</span>
                            <span class="recon-label">Endpoints</span>
                        </div>
                        <div class="recon-stat">
                            <span class="recon-value">${assessment.summary.totalTests}</span>
                            <span class="recon-label">Tests Run</span>
                        </div>
                        <div class="recon-stat">
                            <span class="recon-value">${cookieCount}</span>
                            <span class="recon-label">Cookies</span>
                        </div>
                        <div class="recon-stat">
                            <span class="recon-value">${(assessment.duration / 1000).toFixed(0)}s</span>
                            <span class="recon-label">Duration</span>
                        </div>
                    </div>
                    <div class="recon-details">
                        <p><strong>Tech Stack:</strong> ${techStack.length > 0 ? techStack.map(t => `<span class="tech-badge">${t}</span>`).join(' ') : 'Not detected'}</p>
                        <p><strong>Auth Method:</strong> <span class="auth-badge">${authMechanism}</span></p>
                    </div>
                </div>
                
                <div class="recon-card findings-summary">
                    <h3>🎯 Findings Summary</h3>
                    <div class="findings-grid">
                        <div class="finding-count critical">${assessment.summary.critical}<span>Critical</span></div>
                        <div class="finding-count high">${assessment.summary.high}<span>High</span></div>
                        <div class="finding-count medium">${assessment.summary.medium}<span>Medium</span></div>
                        <div class="finding-count low">${assessment.summary.low}<span>Low</span></div>
                    </div>
                </div>
            </div>
            
            ${findings.length > 0 ? `
            <div class="pentest-findings">
                <h3>🚨 Security Findings</h3>
                <div class="findings-table-wrapper">
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Title</th>
                                <th>Evidence</th>
                                <th>OWASP/CWE</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${findings.map(f => `
                            <tr class="finding-row severity-row-${f.severity.toLowerCase()}">
                                <td><span class="severity-badge severity-${f.severity.toLowerCase()}">${f.severity}</span></td>
                                <td><span class="category-badge">${categoryIcons[f.category] || '🔍'} ${f.category.toUpperCase()}</span></td>
                                <td>
                                    <strong>${this.escapeHtml(f.title)}</strong>
                                    <p class="finding-desc">${this.escapeHtml(f.description)}</p>
                                </td>
                                <td class="evidence-cell">
                                    <code>${this.escapeHtml(f.evidence.substring(0, 100))}${f.evidence.length > 100 ? '...' : ''}</code>
                                </td>
                                <td>
                                    ${f.owaspCategory ? `<span class="owasp-badge">${f.owaspCategory}</span>` : ''}
                                    ${f.cweId ? `<a href="https://cwe.mitre.org/data/definitions/${f.cweId.replace('CWE-', '')}.html" target="_blank" class="cwe-link">${f.cweId}</a>` : ''}
                                </td>
                            </tr>
                            <tr class="remediation-row">
                                <td colspan="5">
                                    <div class="remediation-content">
                                        <strong>🔧 Remediation:</strong> ${this.escapeHtml(f.remediation)}
                                        <br><code class="endpoint-code">${this.escapeHtml(f.endpoint)}</code>
                                    </div>
                                </td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
            ` : '<p class="no-findings">✅ No security vulnerabilities detected during black-box testing</p>'}
            
            ${assessment.reconnaissance.cookies.length > 0 ? `
            <div class="cookie-analysis">
                <h3>🍪 Cookie Security Analysis</h3>
                <table class="cookie-table">
                    <thead>
                        <tr>
                            <th>Cookie Name</th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${assessment.reconnaissance.cookies.map(c => `
                        <tr>
                            <td><code>${this.escapeHtml(c.name)}</code></td>
                            <td class="${c.secure ? 'flag-ok' : 'flag-bad'}">${c.secure ? '✓' : '✗'}</td>
                            <td class="${c.httpOnly ? 'flag-ok' : 'flag-bad'}">${c.httpOnly ? '✓' : '✗'}</td>
                            <td><span class="samesite-badge samesite-${c.sameSite.toLowerCase()}">${c.sameSite}</span></td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            ` : ''}
            ` : ''}
            
            ${supabaseIssues.length > 0 ? `
            <div class="supabase-warning">
                <h3>⚠️ Supabase Security Issues (${supabaseIssues.length})</h3>
                <ul>
                    ${supabaseIssues.map(issue => `
                        <li class="severity-${issue.severity.toLowerCase()}">
                            <strong>[${issue.severity}]</strong> ${this.escapeHtml(issue.description)}
                            <br><em>Remediation: ${this.escapeHtml(issue.remediation)}</em>
                        </li>
                    `).join('')}
                </ul>
            </div>
            ` : ''}
            
            ${vulnLibs.length > 0 ? `
            <div class="vuln-libs-warning">
                <h3>📦 Vulnerable Libraries (${vulnLibs.length})</h3>
                <table class="vuln-libs-table">
                    <thead>
                        <tr>
                            <th>Library</th>
                            <th>Version</th>
                            <th>Severity</th>
                            <th>CVEs</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${vulnLibs.map(lib => `
                        <tr>
                            <td><strong>${this.escapeHtml(lib.name)}</strong></td>
                            <td><code>${lib.version}</code></td>
                            <td><span class="severity-badge severity-${lib.severity.toLowerCase()}">${lib.severity}</span></td>
                            <td>${lib.vulnerabilities.map(v => `<a href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank" class="cve-link">${v.cve}</a>`).join(', ')}</td>
                            <td>${this.escapeHtml(lib.recommendation)}</td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            ` : ''}
            
            ${this.buildVulnIntelligenceSection(report)}
        </section>`;
    }

    /**
     * Build Vulnerability Intelligence Section
     */
    private buildVulnIntelligenceSection(report: ReportData): string {
        const vulnIntel = report.vuln_intelligence;
        if (!vulnIntel || !vulnIntel.enabled) {
            return '';
        }

        const { summary, enrichedLibraries, enrichedAlerts } = vulnIntel;
        const allEnriched = [...enrichedLibraries, ...enrichedAlerts];
        
        // Sort by risk score descending
        allEnriched.sort((a, b) => b.riskScore - a.riskScore);
        const topRisks = allEnriched.slice(0, 10);

        return `
        <div class="vuln-intel-section">
            <h3>🔍 Vulnerability Intelligence</h3>
            <p class="section-subtitle">CVE enrichment, CVSS scoring, and exploit intelligence</p>
            
            <div class="intel-summary-grid">
                <div class="intel-stat">
                    <span class="intel-value">${summary.totalFindings}</span>
                    <span class="intel-label">Total Enriched</span>
                </div>
                <div class="intel-stat critical">
                    <span class="intel-value">${summary.bySeverity.CRITICAL}</span>
                    <span class="intel-label">Critical</span>
                </div>
                <div class="intel-stat high">
                    <span class="intel-value">${summary.bySeverity.HIGH}</span>
                    <span class="intel-label">High</span>
                </div>
                <div class="intel-stat warning">
                    <span class="intel-value">${summary.withExploits}</span>
                    <span class="intel-label">With Exploits</span>
                </div>
                <div class="intel-stat danger">
                    <span class="intel-value">${summary.inKev}</span>
                    <span class="intel-label">In CISA KEV</span>
                </div>
                <div class="intel-stat">
                    <span class="intel-value">${summary.averageRiskScore}</span>
                    <span class="intel-label">Avg Risk Score</span>
                </div>
            </div>
            
            ${topRisks.length > 0 ? `
            <div class="top-risks">
                <h4>🎯 Top Risk Vulnerabilities</h4>
                <table class="intel-table">
                    <thead>
                        <tr>
                            <th>Risk</th>
                            <th>CVE</th>
                            <th>CWE</th>
                            <th>CVSS</th>
                            <th>Exploit</th>
                            <th>KEV</th>
                            <th>Risk Factors</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${topRisks.map(v => `
                        <tr class="risk-row risk-${v.riskScore >= 80 ? 'critical' : v.riskScore >= 60 ? 'high' : v.riskScore >= 40 ? 'medium' : 'low'}">
                            <td>
                                <div class="risk-score-badge" style="background: ${this.getRiskColor(v.riskScore)}">
                                    ${v.riskScore}
                                </div>
                            </td>
                            <td>
                                <a href="https://nvd.nist.gov/vuln/detail/${v.cveId}" target="_blank" class="cve-link">
                                    ${v.cveId}
                                </a>
                            </td>
                            <td>
                                ${v.cwe 
                                    ? `<a href="https://cwe.mitre.org/data/definitions/${v.cwe.id.replace('CWE-', '')}.html" target="_blank" class="cwe-link" title="${this.escapeHtml(v.cwe.description)}">
                                        ${v.cwe.id}<br><small>${this.escapeHtml(v.cwe.name)}</small>
                                    </a>`
                                    : '<span class="cwe-unknown">—</span>'
                                }
                            </td>
                            <td>
                                <span class="cvss-badge cvss-${v.cvss.severity.toLowerCase()}" title="${v.cvss.vector}">
                                    ${v.cvss.baseScore} ${v.cvss.severity}
                                </span>
                            </td>
                            <td>
                                ${v.exploit.available 
                                    ? `<span class="exploit-badge danger">⚠️ ${v.exploit.source || 'Available'}${v.exploit.maturity ? ` (${v.exploit.maturity})` : ''}</span>`
                                    : '<span class="exploit-badge safe">None Known</span>'
                                }
                            </td>
                            <td>
                                ${v.knownExploitedVuln 
                                    ? '<span class="kev-badge danger">🚨 IN KEV</span>'
                                    : '<span class="kev-badge safe">—</span>'
                                }
                            </td>
                            <td>
                                <ul class="risk-factors">
                                    ${v.riskFactors.map(f => `<li>${this.escapeHtml(f)}</li>`).join('')}
                                </ul>
                            </td>
                            <td>
                                <div class="remediation-cell">
                                    <span class="effort-badge effort-${v.remediation.effort}">${v.remediation.effort}</span>
                                    <p>${this.escapeHtml(v.remediation.description)}</p>
                                    ${v.remediation.targetVersion ? `<code>→ v${v.remediation.targetVersion}</code>` : ''}
                                </div>
                            </td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            ` : '<p class="no-intel">No enriched vulnerability data available</p>'}
            
            ${summary.topCves.length > 0 ? `
            <div class="top-cves">
                <h4>📊 Priority CVEs</h4>
                <div class="cve-chips">
                    ${summary.topCves.map(c => `
                        <a href="https://nvd.nist.gov/vuln/detail/${c.cveId}" target="_blank" 
                           class="cve-chip" style="border-color: ${this.getRiskColor(c.riskScore)}">
                            ${c.cveId} <span class="chip-score">${c.riskScore}</span>
                        </a>
                    `).join('')}
                </div>
            </div>
            ` : ''}
        </div>`;
    }

    /**
     * Get color for risk score
     */
    private getRiskColor(score: number): string {
        if (score >= 80) return '#dc3545'; // Critical - red
        if (score >= 60) return '#fd7e14'; // High - orange
        if (score >= 40) return '#ffc107'; // Medium - yellow
        if (score >= 20) return '#28a745'; // Low - green
        return '#6c757d'; // Info - gray
    }

    /**
     * Build the main remediation grid/table
     */
    private buildRemediationGrid(issues: ArchitectIssue[]): string {
        if (issues.length === 0) {
            return `
            <section class="remediation-section">
                <div class="section-header">
                    <h2>Remediation Grid</h2>
                </div>
                <div class="no-issues-large">
                    <span class="success-icon">✅</span>
                    <p>No issues detected. Your site is in great shape!</p>
                </div>
            </section>`;
        }

        // Sort by severity
        const severityOrder = { critical: 0, serious: 1, warning: 2, info: 3 };
        const sortedIssues = [...issues].sort((a, b) =>
            severityOrder[a.severity] - severityOrder[b.severity]
        );

        return `
        <section class="remediation-section">
            <div class="section-header">
                <h2>Remediation Grid</h2>
                <div class="filter-controls">
                    <button class="filter-btn active" data-filter="all">All (${issues.length})</button>
                    <button class="filter-btn" data-filter="critical">Critical (${issues.filter(i => i.severity === 'critical').length})</button>
                    <button class="filter-btn" data-filter="serious">Serious (${issues.filter(i => i.severity === 'serious').length})</button>
                    <button class="filter-btn" data-filter="warning">Warning (${issues.filter(i => i.severity === 'warning').length})</button>
                </div>
            </div>
            <div class="table-wrapper">
                <table class="remediation-table" id="remediationTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="severity">Severity</th>
                            <th class="sortable" data-sort="component">Component</th>
                            <th class="sortable" data-sort="issue">Issue</th>
                            <th>Remediation</th>
                            <th class="sortable" data-sort="effort">Effort</th>
                            <th>Docs</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${sortedIssues.map(issue => `
                        <tr class="issue-row" data-severity="${issue.severity}">
                            <td>
                                <span class="severity-badge severity-${issue.severity}">${issue.severity}</span>
                            </td>
                            <td class="component-cell">
                                <code class="locator" title="Click to copy">${this.escapeHtml(issue.playwrightLocator)}</code>
                                ${issue.nodeCount ? `<span class="node-count">${issue.nodeCount} element${issue.nodeCount > 1 ? 's' : ''}</span>` : ''}
                            </td>
                            <td class="issue-cell">
                                <code class="issue-id">${issue.id}</code>
                                <p class="issue-desc">${this.escapeHtml(issue.issue)}</p>
                            </td>
                            <td class="remediation-cell">
                                <p>${this.escapeHtml(issue.remediation)}</p>
                                ${issue.aiSolution ? `
                                <div class="ai-solution">
                                    <div class="ai-header">
                                        <span class="ai-icon">✨</span>
                                        <strong>AI Suggested Fix</strong>
                                    </div>
                                    <pre><code>${this.escapeHtml(issue.aiSolution)}</code></pre>
                                </div>
                                ` : ''}
                            </td>
                            <td>
                                <span class="effort-badge effort-${issue.effort}">${issue.effort}</span>
                            </td>
                            <td>
                                <a href="${issue.docsUrl}" target="_blank" class="docs-link" title="View documentation">📖</a>
                            </td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </section>`;
    }

    /**
     * Build footer
     */
    private buildFooter(report: ReportData): string {
        const footerText = this.branding.footerText || `${this.branding.companyName} v${report.meta.version}`;
        return `
        <footer class="footer">
            <div class="footer-left">
                <span>${footerText}</span>
            </div>
            <div class="footer-right">
                <span>Audit completed in ${(report.meta.duration / 1000).toFixed(2)}s</span>
            </div>
        </footer>`;
    }

    /**
     * Group issues by category
     */
    private groupIssuesByCategory(issues: ArchitectIssue[]): Record<string, ArchitectIssue[]> {
        return issues.reduce((acc, issue) => {
            if (!acc[issue.category]) {
                acc[issue.category] = [];
            }
            acc[issue.category].push(issue);
            return acc;
        }, {} as Record<string, ArchitectIssue[]>);
    }



    /**
     * Build Trend Chart Section
     */


    /**
     * Escape HTML special characters
     */
    private escapeHtml(str: string): string {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /**
     * Build Multi-Device Analysis section
     */
    private buildMultiDeviceSection(report: ReportData): string {
        if (!report.multi_device || report.multi_device.length === 0) {
            return '';
        }

        return `
        <section class="multi-device-section">
            <div class="section-header">
                <h2>📱 Multi-Device Analysis</h2>
                <div class="filter-controls">
                     <span class="badge badge-info">${report.multi_device.length} Devices Scanned</span>
                </div>
            </div>
            <div class="device-grid">
                ${report.multi_device.map(d => {
            const scores = d.lighthouse?.scores || { performance: 0, accessibility: 0, seo: 0, bestPractices: 0 };
            const avgScore = Math.round((scores.performance + scores.accessibility + scores.seo) / 3);
            const scoreClass = avgScore >= 90 ? 'good' : avgScore >= 70 ? 'warning' : 'critical';

            return `
                    <div class="device-card">
                        <div class="device-header">
                            <h3>${this.escapeHtml(d.device)}</h3>
                            <span class="device-score score-${scoreClass}">${avgScore}</span>
                        </div>
                        <div class="device-metrics">
                            <div class="metric-row">
                                <span>Performance</span>
                                <span class="metric-val ${this.getMetricClass(scores.performance)}">${scores.performance}</span>
                            </div>
                            <div class="metric-row">
                                <span>Accessibility</span>
                                <span class="metric-val ${this.getMetricClass(scores.accessibility)}">${scores.accessibility}</span>
                            </div>
                            <div class="metric-row">
                                <span>SEO</span>
                                <span class="metric-val ${this.getMetricClass(scores.seo)}">${scores.seo}</span>
                            </div>
                        </div>
                        <div class="device-stats">
                            <span title="Pages Visited">📄 ${d.crawlSummary.pagesVisited}</span>
                            <span title="Failed Pages" class="${d.crawlSummary.failedPages > 0 ? 'bad' : ''}">❌ ${d.crawlSummary.failedPages}</span>
                        </div>
                        ${d.screenshotPath ? `
                        <div class="device-screenshot">
                            <img src="${this.getRelativeScreenshotPath(d.screenshotPath)}" alt="Screenshot of ${d.device}" loading="lazy" onclick="window.open(this.src, '_blank')">
                        </div>` : ''}
                    </div>
                `;
        }).join('')}
            </div>
        </section>`;
    }

    private getRelativeScreenshotPath(absPath: string): string {
        try {
            if (fs.existsSync(absPath)) {
                const imageBuffer = fs.readFileSync(absPath);
                return `data:image/png;base64,${imageBuffer.toString('base64')}`;
            }
        } catch { }
        return 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj48dGV4dCB4PSI1MCUiIHk9IjUwJSIgZG9taW5hbnQtYmFzZWxpbmU9Im1pZGRsZSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxNCI+Tm8gSW1hZ2U8L3RleHQ+PC9zdmc+';
    }

    private getScoreRingClass(score: number): string {
        if (score >= 90) return 'score-good';
        if (score >= 70) return 'score-warning';
        return 'score-critical';
    }

    private getMetricClass(score: number): string {
        return score >= 90 ? 'good' : 'bad';
    }

    private getCoverageBadgeClass(status: string): string {
        switch (status) {
            case 'ran': return 'badge-success';
            case 'failed': return 'badge-critical';
            default: return 'badge-warning';
        }
    }

    /**
     * Build HTML Content
     */
    private buildHtml(report: ReportData, issues: ArchitectIssue[], healthScore: number, quickWins: ArchitectIssue[], history: RunSummary[]): string {
        const generationDate = new Date().toLocaleString();

        // Calculate Compliance Summary
        const complianceCounts: Record<string, number> = {};
        issues.forEach(issue => {
            issue.complianceTags?.forEach(tag => {
                // Group by main standard (e.g., "WCAG 2.1 AA" -> "WCAG")
                const standardKey = tag;
                complianceCounts[standardKey] = (complianceCounts[standardKey] || 0) + 1;
            });
        });

        // Sort top 4 compliance risks
        const topCompliance = Object.entries(complianceCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 4);

        // Build branding elements
        const reportTitle = this.branding.reportTitle 
            ? `${this.branding.reportTitle} Compliance Report`
            : 'Compliance Executive Report';
        const logoHtml = this.branding.logoUrl 
            ? `<img src="${this.branding.logoUrl}" alt="${this.branding.companyName}" class="brand-logo" />`
            : '';
        const customCssLink = this.branding.customCssUrl 
            ? `<link rel="stylesheet" href="${this.branding.customCssUrl}" />`
            : '';
        const pagesVisited = report.crawl?.pagesVisited ?? 0;
        const securityAlertsCount = (report.security_alerts?.length ?? 0) + (report.security_assessment?.findings?.length ?? 0);
        const durationSeconds = ((report.meta?.duration ?? 0) / 1000).toFixed(1);

        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${reportTitle} - ${this.extractDomainName(report.meta.targetUrl)}</title>
    <style>${this.getStyles()}</style>
    ${customCssLink}
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-left">
                ${logoHtml}
                <div class="header-text">
                    <h1>${reportTitle}</h1>
                    <p>Generated on ${generationDate} for <a href="${report.meta.targetUrl}" target="_blank" style="color:var(--accent-blue)">${report.meta.targetUrl}</a></p>
                </div>
            </div>
            <div class="health-score">
                <div class="score-ring ${this.getScoreRingClass(healthScore)}">
                    <svg viewBox="0 0 36 36">
                        <path class="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path class="ring-fill" stroke-dasharray="${healthScore}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    </svg>
                    <div class="score-number">${healthScore}</div>
                </div>
                <div class="score-label">Health Score</div>
            </div>
        </header>

        <!-- Compliance Summary Cards -->
        ${topCompliance.length > 0 ? `
        <div class="section-header"><h2>Regulatory Compliance Risks</h2></div>
        <div class="compliance-section">
            ${topCompliance.map(([standard, count]) => `
            <div class="compliance-card">
                <div class="compliance-standard">${standard}</div>
                <div class="compliance-count">${count} Violations</div>
            </div>
            `).join('')}
        </div>
        ` : ''}

        <!-- Environment Info -->
        <div class="env-bar">
            <div class="env-item">
                <span class="env-icon">⏱️</span>
                <div>
                    <div class="env-label">Duration</div>
                    <div class="env-value">${durationSeconds}s</div>
                </div>
            </div>
            ${report.meta?.profile ? `
            <div class="env-item">
                <span class="env-icon">🧭</span>
                <div>
                    <div class="env-label">Profile</div>
                    <div class="env-value">${report.meta.profile}</div>
                </div>
            </div>
            ` : ''}
            ${report.meta?.runId ? `
            <div class="env-item">
                <span class="env-icon">🆔</span>
                <div>
                    <div class="env-label">Run ID</div>
                    <div class="env-value">${report.meta.runId}</div>
                </div>
            </div>
            ` : ''}
            <div class="env-item">
                <span class="env-icon">📄</span>
                <div>
                    <div class="env-label">Pages Audit</div>
                    <div class="env-value">${pagesVisited}</div>
                </div>
            </div>
            <div class="env-item">
                <span class="env-icon">🛡️</span>
                <div>
                    <div class="env-label">Security Alerts</div>
                    <div class="env-value">${securityAlertsCount}</div>
                </div>
            </div>
            <div class="env-item">
                <span class="env-icon">♿</span>
                <div>
                    <div class="env-label">A11y Violations</div>
                    <div class="env-value">${issues.filter(i => i.category === 'accessibility').length}</div>
                </div>
            </div>
        </div>

        <!-- Coverage Summary -->
        ${report.coverage && report.coverage.length > 0 ? `
        <div class="section-header"><h2>Scan Coverage</h2></div>
        <div class="compliance-section">
            ${report.coverage.map(item => {
                const badgeClass = this.getCoverageBadgeClass(item.status);
                const statusLabel = item.status === 'ran' ? 'Ran' : (item.status === 'failed' ? 'Failed' : 'Skipped');
                return `
                <div class="compliance-card">
                    <div class="compliance-standard">${item.name}</div>
                    <div class="compliance-count"><span class="badge ${badgeClass}">${statusLabel}</span></div>
                    ${item.detail ? `<div class="compliance-count">${item.detail}</div>` : ''}
                </div>
                `;
            }).join('')}
        </div>
        ` : ''}

        <!-- Multi-Device Analysis -->
        ${this.buildMultiDeviceSection(report)}

        <!-- Trend Chart -->
        <div class="trend-section">
            <div class="section-header">
                <h2>Compliance Trend (Last 5 Runs)</h2>
                <div class="filter-controls">
                    <select id="trendMetric" class="metric-select" onchange="updateTrendChart()">
                        <option value="health">Health Score</option>
                        <option value="critical">Critical Issues</option>
                        <option value="performance">Performance</option>
                    </select>
                </div>
            </div>
            <div class="chart-container">
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <!-- Quick Wins -->
        ${quickWins.length > 0 ? `
        <div class="quick-wins-card success">
            <div class="quick-wins-header">
                <h2>⚡ Quick Wins (High Impact, Low Effort)</h2>
            </div>
            <div class="quick-wins-list">
                ${quickWins.map((win, index) => `
                <div class="quick-win-item">
                    <div class="quick-win-number">${index + 1}</div>
                    <div class="quick-win-content">
                        <div class="quick-win-header">
                            <span class="badge badge-critical">${win.category}</span>
                            <strong>${win.id}</strong>
                            ${win.complianceTags?.map(tag => `<span class="compliance-badge">${tag}</span>`).join('') || ''}
                        </div>
                        <div class="quick-win-issue">${win.issue}</div>
                        <div class="quick-win-fix">👉 ${win.remediation}</div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <!-- Remediation Table -->
        <div class="remediation-section">
            <div class="section-header">
                <h2>Remediation Plan (${issues.length} Issues)</h2>
                <div class="filter-controls">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" id="searchInput" placeholder="Search findings..." aria-label="Search findings">
                    </div>
                    <div class="filter-group">
                        <button class="filter-btn active" data-filter="all">All</button>
                        <button class="filter-btn" data-filter="critical">Critical</button>
                        <button class="filter-btn" data-filter="serious">Serious</button>
                        <button class="filter-btn" data-filter="warning">Warning</button>
                    </div>
                    <div class="action-group">
                        <button class="action-btn" id="exportBtn" onclick="exportReportJson()">📥 Export JSON</button>
                    </div>
                </div>
            </div>

            <div class="table-wrapper">
                ${issues.length === 0 ? `
                <div class="no-issues-large">
                    <span class="success-icon">🎉</span>
                    <p>No issues detected! Your application is compliant.</p>
                </div>
                ` : `
                <table class="remediation-table" id="remediationTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="severity">Severity</th>
                            <th class="sortable" data-sort="component">Component / Locator</th>
                            <th class="sortable" data-sort="issue">Issue & Remediation</th>
                            <th>Docs</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${issues.map(issue => `
                        <tr class="issue-row" data-severity="${issue.severity}">
                            <td><span class="severity-badge severity-${issue.severity}">${issue.severity}</span><br><br><span class="effort-badge effort-${issue.effort}">${issue.effort} Effort</span></td>
                            <td class="component-cell">
                                <div style="font-weight:600; margin-bottom:4px;">${issue.component}</div>
                                <code class="locator" title="Click to copy">${issue.playwrightLocator}</code>
                                ${issue.nodeCount ? `<span class="node-count">${issue.nodeCount} occurrences</span>` : ''}
                            </td>
                            <td class="issue-cell">
                                <span class="issue-id">${issue.id}</span>
                                ${issue.complianceTags?.map(tag => `<span class="compliance-badge">${tag}</span>`).join('') || ''}
                                <div class="issue-desc">${issue.issue}</div>
                                <div style="margin-top:8px; padding-top:8px; border-top:1px dashed var(--border-color);">
                                    <strong>Fix:</strong> ${issue.remediation}
                                </div>
                                ${issue.aiSolution ? `
                                <div class="ai-solution" style="margin-top:12px;">
                                    <div class="ai-header">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/><path d="M12 6a1 1 0 0 0-1 1v4H7a1 1 0 0 0 0 2h4v4a1 1 0 0 0 2 0v-4h4a1 1 0 0 0 0-2h-4V7a1 1 0 0 0-1-1z"/></svg>
                                        AI Suggested Fix
                                    </div>
                                    <pre><code>${issue.aiSolution.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>
                                </div>
                                ` : ''}
                            </td>
                            <td><a href="${issue.docsUrl}" target="_blank" class="docs-link" title="View Documentation">📚</a></td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
                `}
            </div>
        </div>

        <footer class="footer">
            <div>${this.branding.footerText || `Generated by ${this.branding.companyName}`}</div>
            <div>${report.meta.version || 'v1.0.0'}</div>
        </footer>
    </div>
    <script>
        const reportData = ${JSON.stringify(report)};
        ${this.getScripts()}
    </script>
    <script>
        // Initialize Trend Chart
        const ctx = document.getElementById('trendChart').getContext('2d');
        const historyData = ${JSON.stringify(history)};
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: historyData.dates.map(d => new Date(d).toLocaleDateString()),
                datasets: [
                    {
                        label: 'Health Score',
                        data: historyData.healthScores,
                        borderColor: '#3fb950',
                        tension: 0.4
                    },
                    {
                        label: 'Critical Issues',
                        data: historyData.criticalCounts,
                        borderColor: '#f85149',
                        borderDash: [5, 5],
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                },
                scales: {
                    y: { beginAtZero: true, max: 100 }
                }
            }
        });
    </script>
</body>
</html>
        `;
    } // End buildHtml

    /**
     * Get embedded CSS styles
     */
    private getStyles(): string {
        return `
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-hover: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-color: #30363d;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-orange: #db6d28;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --brand-primary: ${this.branding.primaryColor};
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 24px;
        }

        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 24px 32px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 16px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-logo {
            max-height: 50px;
            max-width: 200px;
            object-fit: contain;
        }

        .header-text { display: flex; flex-direction: column; }

        .header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            background: linear-gradient(90deg, var(--text-primary), var(--brand-primary, var(--accent-blue)));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .meta-info { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
        .domain { font-size: 1.1rem; color: var(--accent-blue); font-weight: 600; }
        .target-url { font-size: 0.85rem; color: var(--text-secondary); text-decoration: none; }
        .target-url:hover { color: var(--accent-blue); }
        .timestamp { font-size: 0.8rem; color: var(--text-muted); }
        .active-scan-badge {
            display: inline-block;
            background: rgba(248, 81, 73, 0.15);
            color: var(--accent-red);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            border: 1px solid rgba(248, 81, 73, 0.4);
            margin-top: 4px;
            width: fit-content;
        }

        /* Health Gauge */
        .health-gauge { width: 140px; height: 80px; }
        .gauge-svg { width: 100%; height: 100%; }
        .gauge-bg {
            fill: none;
            stroke: var(--bg-tertiary);
            stroke-width: 10;
            stroke-linecap: round;
        }
        .gauge-fill {
            fill: none;
            stroke-width: 10;
            stroke-linecap: round;
            transition: stroke-dasharray 1s ease;
        }
        .gauge-value {
            font-size: 24px;
            font-weight: 700;
            fill: var(--text-primary);
            text-anchor: middle;
        }
        .gauge-label {
            font-size: 8px;
            fill: var(--text-secondary);
            text-anchor: middle;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Compliance Section */
        .compliance-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .compliance-card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 16px 20px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        .compliance-standard {
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 4px;
        }
        .compliance-count {
            font-size: 0.8rem;
            color: var(--accent-red);
        }
        .compliance-badge {
            display: inline-block;
            padding: 2px 8px;
            background: rgba(163,113,247,0.15);
            color: var(--accent-purple);
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-left: 4px;
        }

        /* Environment Bar */
        .env-bar {
            display: flex;
            justify-content: space-around;
            padding: 16px;
            background: var(--bg-secondary);
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        .env-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .env-icon { font-size: 1.2rem; }
        .env-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
        .env-value { font-size: 0.9rem; color: var(--text-primary); font-weight: 500; }

        /* Quick Wins Card */
        .quick-wins-card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--accent-blue);
        }
        .quick-wins-card.success { border-color: var(--accent-green); }
        .quick-wins-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .quick-wins-header h2 { font-size: 1.1rem; }
        .quick-wins-list { display: flex; flex-direction: column; gap: 12px; }
        .quick-win-item {
            display: flex;
            gap: 16px;
            padding: 16px;
            background: var(--bg-tertiary);
            border-radius: 8px;
        }
        .quick-win-number {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            background: var(--accent-blue);
            color: var(--bg-primary);
            border-radius: 50%;
            font-weight: 700;
            flex-shrink: 0;
        }
        .quick-win-content { flex: 1; }
        .quick-win-header { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
        .quick-win-issue { color: var(--text-secondary); margin-bottom: 8px; }
        .quick-win-fix { font-size: 0.9rem; color: var(--text-primary); }

        /* Badges */
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-success { background: rgba(63,185,80,0.15); color: var(--accent-green); }
        .badge-warning { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }
        .badge-info { background: rgba(88,166,255,0.15); color: var(--accent-blue); }

        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .severity-critical { background: rgba(248,81,73,0.2); color: var(--accent-red); }
        .severity-serious { background: rgba(219,109,40,0.2); color: var(--accent-orange); }
        .severity-warning { background: rgba(210,153,34,0.2); color: var(--accent-yellow); }
        .severity-info { background: rgba(88,166,255,0.2); color: var(--accent-blue); }

        .effort-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .effort-low { background: rgba(63,185,80,0.15); color: var(--accent-green); }
        .effort-medium { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }
        .effort-high { background: rgba(248,81,73,0.15); color: var(--accent-red); }

        .issue-id {
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.8rem;
            color: var(--accent-purple);
            background: var(--bg-primary);
            padding: 2px 6px;
            border-radius: 4px;
        }

        /* Score Section */
        .score-section { margin-bottom: 20px; }
        .score-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 16px;
        }
        .score-card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border-color);
        }
        .score-ring { position: relative; width: 80px; height: 80px; margin: 0 auto 12px; }
        .score-ring svg { transform: rotate(-90deg); }
        .ring-bg { fill: none; stroke: var(--bg-tertiary); stroke-width: 3; }
        .ring-fill { fill: none; stroke-width: 3; stroke-linecap: round; transition: stroke-dasharray 1s; }
        .score-good .ring-fill { stroke: var(--accent-green); }
        .score-warning .ring-fill { stroke: var(--accent-yellow); }
        .score-critical .ring-fill { stroke: var(--accent-red); }
        .score-number {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.5rem;
            font-weight: 700;
        }
        .score-good .score-number { color: var(--accent-green); }
        .score-warning .score-number { color: var(--accent-yellow); }
        .score-critical .score-number { color: var(--accent-red); }
        .score-label { font-size: 0.85rem; color: var(--text-secondary); }

        /* Metrics Bar */
        .metrics-bar {
            display: flex;
            justify-content: space-around;
            padding: 16px;
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }
        .metric { text-align: center; }
        .metric-value { font-size: 1.1rem; font-weight: 700; display: block; }
        .metric-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; }
        .metric.good .metric-value { color: var(--accent-green); }
        .metric.warning .metric-value { color: var(--accent-yellow); }
        .metric.critical .metric-value { color: var(--accent-red); }

        /* Remediation Section */
        .remediation-section {
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }
        .section-header h2 { font-size: 1rem; }
        .filter-controls { display: flex; gap: 8px; }
        .filter-btn {
            padding: 6px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--accent-blue); color: var(--text-primary); }
        .filter-btn.active { background: var(--accent-blue); color: var(--bg-primary); border-color: var(--accent-blue); }

        .table-wrapper { overflow-x: auto; }
        .remediation-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        .remediation-table th {
            text-align: left;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
            white-space: nowrap;
        }
        .remediation-table th.sortable { cursor: pointer; }
        .remediation-table th.sortable:hover { color: var(--accent-blue); }
        .remediation-table td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }
        .remediation-table tr:hover { background: var(--bg-hover); }
        .remediation-table tr.hidden { display: none; }

        .component-cell { max-width: 280px; }
        .locator {
            display: block;
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.75rem;
            color: var(--accent-blue);
            background: var(--bg-primary);
            padding: 8px;
            border-radius: 4px;
            word-break: break-all;
            cursor: pointer;
            transition: background 0.2s;
        }
        .locator:hover { background: var(--bg-tertiary); }
        .locator.copied { background: var(--accent-green); color: var(--bg-primary); }
        .node-count { display: block; font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }

        .issue-cell { max-width: 300px; }
        .issue-cell .issue-id { display: inline-block; margin-bottom: 6px; }
        .issue-desc { color: var(--text-secondary); font-size: 0.85rem; }

        .remediation-cell { max-width: 400px; }
        .remediation-cell p { color: var(--text-secondary); font-size: 0.85rem; }

        .docs-link {
            display: inline-block;
            font-size: 1.2rem;
            text-decoration: none;
            opacity: 0.7;
            transition: opacity 0.2s;
        }
        .docs-link:hover { opacity: 1; }

        /* No Issues */
        .no-issues { color: var(--accent-green); text-align: center; padding: 16px; }
        .no-issues-large {
            padding: 60px;
            text-align: center;
        }
        .success-icon { font-size: 3rem; display: block; margin-bottom: 16px; }
        .no-issues-large p { color: var(--text-secondary); font-size: 1.1rem; }

        /* Footer */
        .footer {
            display: flex;
            justify-content: space-between;
            padding: 20px;
            margin-top: 24px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        /* Security Assessment Section */
        .security-assessment-section {
            margin: 24px 0;
            padding: 24px;
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }
        .security-assessment-section h2 {
            font-size: 1.3rem;
            margin-bottom: 20px;
        }
        .recon-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .recon-card {
            background: var(--bg-tertiary);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }
        .recon-card h3 {
            font-size: 1rem;
            margin-bottom: 16px;
            color: var(--accent-blue);
        }
        .recon-stats {
            display: flex;
            gap: 24px;
            margin-bottom: 16px;
        }
        .recon-stat {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .recon-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .recon-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        .recon-details p {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin: 4px 0;
        }
        .findings-summary .findings-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }
        .finding-count {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 16px 8px;
            border-radius: 8px;
            font-size: 2rem;
            font-weight: 700;
        }
        .finding-count span {
            font-size: 0.7rem;
            font-weight: 400;
            text-transform: uppercase;
            margin-top: 4px;
        }
        .finding-count.critical {
            background: rgba(248, 81, 73, 0.15);
            color: var(--accent-red);
        }
        .finding-count.high {
            background: rgba(219, 109, 40, 0.15);
            color: var(--accent-orange);
        }
        .finding-count.medium {
            background: rgba(210, 153, 34, 0.15);
            color: var(--accent-yellow);
        }
        .finding-count.low {
            background: rgba(88, 166, 255, 0.15);
            color: var(--accent-blue);
        }
        .supabase-warning, .vuln-libs-warning {
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--accent-red);
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
        }
        .supabase-warning h3, .vuln-libs-warning h3 {
            color: var(--accent-red);
            font-size: 0.95rem;
            margin-bottom: 12px;
        }
        .supabase-warning ul, .vuln-libs-warning ul {
            list-style: none;
            padding: 0;
        }
        .supabase-warning li, .vuln-libs-warning li {
            font-size: 0.85rem;
            color: var(--text-secondary);
            padding: 8px 0;
            border-bottom: 1px solid rgba(248, 81, 73, 0.2);
        }
        .supabase-warning li:last-child, .vuln-libs-warning li:last-child {
            border-bottom: none;
        }
        .badge-critical {
            background: var(--accent-red);
            color: white;
        }

        /* Security Findings Table */
        .pentest-findings {
            margin-top: 24px;
        }
        .pentest-findings h3 {
            font-size: 1.1rem;
            margin-bottom: 16px;
            color: var(--accent-red);
        }
        .findings-table-wrapper {
            overflow-x: auto;
        }
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .findings-table th, .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        .findings-table th {
            background: var(--bg-tertiary);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        .finding-row:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        .severity-row-critical {
            border-left: 4px solid var(--accent-red);
        }
        .severity-row-high {
            border-left: 4px solid var(--accent-orange);
        }
        .severity-row-medium {
            border-left: 4px solid var(--accent-yellow);
        }
        .severity-row-low, .severity-row-info {
            border-left: 4px solid var(--accent-blue);
        }
        .finding-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .evidence-cell code {
            font-size: 0.75rem;
            background: var(--bg-primary);
            padding: 4px 8px;
            border-radius: 4px;
            display: block;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .remediation-row {
            background: var(--bg-tertiary);
        }
        .remediation-row td {
            padding: 8px 12px;
        }
        .remediation-content {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        .endpoint-code {
            font-size: 0.75rem;
            color: var(--accent-blue);
            margin-top: 4px;
            display: inline-block;
        }
        .category-badge {
            background: var(--bg-primary);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .owasp-badge {
            background: rgba(163, 113, 247, 0.15);
            color: var(--accent-purple);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.65rem;
            display: block;
            margin-bottom: 4px;
        }
        .cwe-link {
            color: var(--accent-blue);
            text-decoration: none;
            font-size: 0.75rem;
        }
        .cwe-link:hover {
            text-decoration: underline;
        }
        .cve-link {
            color: var(--accent-red);
            text-decoration: none;
            font-size: 0.8rem;
        }
        .cve-link:hover {
            text-decoration: underline;
        }
        .no-findings {
            text-align: center;
            color: var(--accent-green);
            padding: 20px;
            font-size: 1rem;
        }

        /* Cookie Analysis */
        .cookie-analysis {
            margin-top: 24px;
        }
        .cookie-analysis h3 {
            font-size: 1rem;
            margin-bottom: 12px;
            color: var(--accent-blue);
        }
        .cookie-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .cookie-table th, .cookie-table td {
            padding: 10px;
            text-align: center;
            border-bottom: 1px solid var(--border-color);
        }
        .cookie-table th {
            background: var(--bg-tertiary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        .cookie-table td:first-child {
            text-align: left;
        }
        .flag-ok {
            color: var(--accent-green);
            font-size: 1.2rem;
        }
        .flag-bad {
            color: var(--accent-red);
            font-size: 1.2rem;
        }
        .samesite-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .samesite-strict {
            background: rgba(63, 185, 80, 0.2);
            color: var(--accent-green);
        }
        .samesite-lax {
            background: rgba(210, 153, 34, 0.2);
            color: var(--accent-yellow);
        }
        .samesite-none {
            background: rgba(248, 81, 73, 0.2);
            color: var(--accent-red);
        }

        /* Tech Stack & Auth Badges */
        .tech-badge {
            background: rgba(88, 166, 255, 0.15);
            color: var(--accent-blue);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-right: 4px;
        }
        .auth-badge {
            background: rgba(163, 113, 247, 0.15);
            color: var(--accent-purple);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }

        /* Vulnerable Libraries Table */
        .vuln-libs-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-top: 12px;
        }
        .vuln-libs-table th, .vuln-libs-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid rgba(248, 81, 73, 0.2);
        }
        .vuln-libs-table th {
            background: rgba(248, 81, 73, 0.1);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            color: var(--accent-red);
        }

        /* Vulnerability Intelligence Section */
        .vuln-intel-section {
            margin-top: 24px;
            padding: 20px;
            background: rgba(88, 166, 255, 0.05);
            border-radius: 12px;
            border: 1px solid rgba(88, 166, 255, 0.2);
        }
        .vuln-intel-section h3 {
            margin: 0 0 8px 0;
            color: var(--accent-blue);
        }
        .section-subtitle {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-bottom: 16px;
        }
        .intel-summary-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        .intel-stat {
            text-align: center;
            padding: 16px 12px;
            background: var(--bg-card);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        .intel-stat.critical { border-color: var(--accent-red); background: rgba(248, 81, 73, 0.1); }
        .intel-stat.high { border-color: #fd7e14; background: rgba(253, 126, 20, 0.1); }
        .intel-stat.warning { border-color: var(--accent-yellow); background: rgba(255, 193, 7, 0.1); }
        .intel-stat.danger { border-color: #dc3545; background: rgba(220, 53, 69, 0.1); }
        .intel-value {
            display: block;
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .intel-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        .intel-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-top: 12px;
        }
        .intel-table th, .intel-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        .intel-table th {
            background: var(--bg-card);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        .risk-score-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            color: white;
            font-weight: 700;
            font-size: 0.9rem;
        }
        .cvss-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .cvss-critical { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .cvss-high { background: rgba(253, 126, 20, 0.2); color: #fd7e14; }
        .cvss-medium { background: rgba(255, 193, 7, 0.2); color: #d39e00; }
        .cvss-low { background: rgba(40, 167, 69, 0.2); color: var(--accent-green); }
        .cvss-none { background: var(--bg-card); color: var(--text-muted); }
        .exploit-badge, .kev-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
        .exploit-badge.danger, .kev-badge.danger {
            background: rgba(220, 53, 69, 0.2);
            color: #dc3545;
        }
        .exploit-badge.safe, .kev-badge.safe {
            background: var(--bg-card);
            color: var(--text-muted);
        }
        .risk-factors {
            margin: 0;
            padding-left: 16px;
            font-size: 0.75rem;
        }
        .risk-factors li {
            margin: 2px 0;
        }
        .effort-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .effort-low { background: rgba(40, 167, 69, 0.2); color: var(--accent-green); }
        .effort-medium { background: rgba(255, 193, 7, 0.2); color: #d39e00; }
        .effort-high { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .remediation-cell p {
            margin: 4px 0;
            font-size: 0.8rem;
        }
        .top-cves {
            margin-top: 16px;
        }
        .cve-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .cve-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 20px;
            border: 2px solid;
            background: var(--bg-card);
            color: var(--text-primary);
            text-decoration: none;
            font-size: 0.85rem;
            transition: transform 0.2s;
        }
        .cve-chip:hover {
            transform: translateY(-2px);
        }
        .chip-score {
            background: rgba(0,0,0,0.2);
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .no-intel {
            color: var(--text-muted);
            font-style: italic;
        }

        /* Score grid with 5 cards */
        .score-grid {
            grid-template-columns: repeat(5, 1fr);
        }

        /* Responsive */
        @media (max-width: 1200px) {
            .score-grid { grid-template-columns: repeat(3, 1fr); }
            .recon-grid { grid-template-columns: 1fr; }
            .findings-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 1024px) {
            .score-grid { grid-template-columns: repeat(2, 1fr); }
            .env-bar { flex-wrap: wrap; gap: 16px; }
        }
        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; gap: 20px; }
            .score-grid { grid-template-columns: 1fr 1fr; }
            .metrics-bar { flex-wrap: wrap; gap: 16px; }
            .filter-controls { flex-wrap: wrap; }
            .findings-grid { grid-template-columns: repeat(2, 1fr); }
        }
        }
        
        .ai-solution {
            margin-top: 12px;
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid rgba(88, 166, 255, 0.2);
            border-radius: 6px;
            padding: 12px;
        }
        .ai-header {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 8px;
            color: var(--accent-blue);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        .ai-header {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 8px;
            color: var(--accent-blue);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        .ai-solution pre {
            background: var(--bg-primary);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85em;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        /* Multi-Device Section */
        .multi-device-section { margin-bottom: 24px; }
        .device-grid {
            display: grid;
            /* Adaptive columns: min 280px */
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        .device-card {
            background: var(--bg-tertiary);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, border-color 0.2s;
        }
        .device-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
        }
        .device-header h3 { margin: 0; font-size: 1.1rem; color: var(--text-primary); text-transform: capitalize; }
        .device-score {
            font-size: 1.2rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 8px;
            background: var(--bg-primary);
        }
        .device-score.score-good { color: var(--accent-green); }
        .device-score.score-warning { color: var(--accent-yellow); }
        .device-score.score-critical { color: var(--accent-red); }

        .device-metrics { margin-bottom: 16px; }
        .metric-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }
        .metric-val { font-weight: 600; }
        .metric-val.good { color: var(--accent-green); }
        .metric-val.bad { color: var(--accent-red); }
        
        .device-stats {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        .device-stats .bad { color: var(--accent-red); font-weight: 600; }

        .device-screenshot {
            margin-top: 16px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            position: relative;
        }
        .device-screenshot img {
            width: 100%;
            height: auto;
            display: block;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .device-screenshot img:hover { opacity: 0.9; }

        @media print {
            .device-card { break-inside: avoid; }
            .score-section, .trend-section, .remediation-section { break-inside: avoid; page-break-inside: avoid; }
            .header { break-after: avoid; }
            .footer { break-before: avoid; }
        }

        /* Trend Chart */
        .trend-section {
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
            padding: 20px;
        }
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        `;
    }

    /**
     * Get embedded JavaScript
     */
    private getScripts(): string {
        return `
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const term = e.target.value.toLowerCase();
                filterIssues(term);
            });
        }

        // Filter functionality
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Re-apply filter with current search term
                const term = document.getElementById('searchInput')?.value.toLowerCase() || '';
                filterIssues(term);
            });
        });

        function filterIssues(searchTerm) {
            const activeServerityBtn = document.querySelector('.filter-btn.active');
            const severityFilter = activeServerityBtn ? activeServerityBtn.dataset.filter : 'all';
            
            document.querySelectorAll('.issue-row').forEach(row => {
                const text = row.textContent.toLowerCase();
                const severity = row.dataset.severity;
                
                const matchesSearch = text.includes(searchTerm);
                const matchesSeverity = severityFilter === 'all' || severity === severityFilter;
                
                if (matchesSearch && matchesSeverity) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }

        // Export JSON
        function exportReportJson() {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
            const downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", "compliance-report.json");
            document.body.appendChild(downloadAnchorNode);
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        }

        // Update Trend Chart
        function updateTrendChart() {
            const metric = document.getElementById('trendMetric').value;
            const chart = Chart.getChart(document.getElementById('trendChart'));
            
            // We need historyData to be available in this scope too, or we can look at the datasets
            // Since historyData is defined in the next script block, we might need to modify how it's initialized.
            // CAUTION: 'historyData' is defined in the *next* script tag in buildHtml.
            // We should reload the chart data there or move the chart initialization here.
            // For now, let's assume the chart is accessible and we can toggle datasets.
            
            if (!chart) return;

            // Simple preset toggling based on datasets we defined
            if (metric === 'health') {
                chart.data.datasets[0].hidden = false;
                chart.data.datasets[1].hidden = true;
            } else if (metric === 'critical') {
                chart.data.datasets[0].hidden = true;
                chart.data.datasets[1].hidden = false;
            } else {
                // Future: Add performance dataset
                chart.data.datasets[0].hidden = false;
                chart.data.datasets[1].hidden = false;
            }
            chart.update();
        }

        // Copy locator to clipboard
        document.querySelectorAll('.locator').forEach(el => {
            el.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(el.textContent);
                    el.classList.add('copied');
                    setTimeout(() => el.classList.remove('copied'), 1000);
                } catch (err) {
                    console.error('Failed to copy:', err);
                }
            });
        });

        // Table sorting
        document.querySelectorAll('.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const table = document.getElementById('remediationTable');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const column = th.dataset.sort;
                const isAsc = th.classList.contains('asc');

                // Remove sort classes from all headers
                document.querySelectorAll('.sortable').forEach(h => {
                    h.classList.remove('asc', 'desc');
                });

                // Add sort class to clicked header
                th.classList.add(isAsc ? 'desc' : 'asc');

                // Sort rows
                const severityOrder = { critical: 0, serious: 1, warning: 2, info: 3 };
                const effortOrder = { low: 0, medium: 1, high: 2 };

                rows.sort((a, b) => {
                    let aVal, bVal;

                    if (column === 'severity') {
                        aVal = severityOrder[a.dataset.severity] || 99;
                        bVal = severityOrder[b.dataset.severity] || 99;
                    } else if (column === 'effort') {
                        aVal = effortOrder[a.querySelector('.effort-badge')?.textContent.trim()] || 99;
                        bVal = effortOrder[b.querySelector('.effort-badge')?.textContent.trim()] || 99;
                    } else {
                        aVal = a.cells[column === 'component' ? 1 : 2]?.textContent || '';
                        bVal = b.cells[column === 'component' ? 1 : 2]?.textContent || '';
                    }

                    if (typeof aVal === 'number') {
                        return isAsc ? bVal - aVal : aVal - bVal;
                    }
                    return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
                });

                // Re-append sorted rows
                rows.forEach(row => tbody.appendChild(row));
            });
        });
        `;
    }
    /**
     * Generate PDF from the HTML report
     * @param htmlFilePath - Absolute path to the source HTML file
     * @param outputPdfPath - Absolute path where PDF should be saved
     */
    async generatePdf(htmlFilePath: string, outputPdfPath: string): Promise<void> {
        logger.info(`Generating PDF report: ${outputPdfPath}`);

        let browser;
        try {
            browser = await chromium.launch({ headless: true });
            const page = await browser.newPage();

            // Convert to file URL (ensure absolute path)
            const absolutePath = path.resolve(htmlFilePath);
            const fileUrl = 'file://' + absolutePath.replace(/\\/g, '/');
            await page.goto(fileUrl, { waitUntil: 'networkidle' });

            // Generate PDF
            await page.pdf({
                path: outputPdfPath,
                format: 'A4',
                printBackground: true,
                margin: {
                    top: '1cm',
                    bottom: '1cm',
                    left: '1cm',
                    right: '1cm'
                },
                displayHeaderFooter: true,
                headerTemplate: '<div style="font-size: 10px; margin-left: 20px;">Compliance Executive Report</div>',
                footerTemplate: '<div style="font-size: 10px; margin-left: 20px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>'
            });

            logger.info('PDF generated successfully');
        } catch (error) {
            logger.error(`PDF generation failed: ${error}`);
        } finally {
            if (browser) {
                await browser.close();
            }
        }
    }
}

export default HtmlReportGenerator;
