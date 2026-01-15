/**
 * Lighthouse Service
 * Performance and accessibility auditing
 */

import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import { PerformanceMetrics, AccessibilityMetrics, Logger } from '../types';

export class LighthouseService {
    private readonly logger: Logger;
    private chrome: chromeLauncher.LaunchedChrome | null = null;

    constructor(logger: Logger) {
        this.logger = logger;
    }

    /**
     * Run Lighthouse audit on URL
     */
    async runAudit(url: string): Promise<{
        performance: PerformanceMetrics;
        accessibility: AccessibilityMetrics;
    }> {
        this.logger.info(`Running Lighthouse audit on: ${url}`);

        try {
            // Launch Chrome for Lighthouse
            this.chrome = await chromeLauncher.launch({
                chromeFlags: ['--headless', '--no-sandbox', '--disable-gpu'],
            });

            // Run Lighthouse
            const result = await lighthouse(url, {
                port: this.chrome.port,
                output: 'json',
                logLevel: 'error',
                onlyCategories: ['performance', 'accessibility'],
            });

            if (!result || !result.lhr) {
                throw new Error('Lighthouse returned no results');
            }

            const { lhr } = result;

            // Extract performance metrics
            const performance = this.extractPerformanceMetrics(lhr);

            // Extract accessibility metrics
            const accessibility = this.extractAccessibilityMetrics(lhr);

            this.logger.info('Lighthouse audit completed', {
                performanceScore: performance.score,
                accessibilityScore: accessibility.score,
            });

            return { performance, accessibility };
        } finally {
            await this.close();
        }
    }

    /**
     * Extract performance metrics from Lighthouse result
     */
    private extractPerformanceMetrics(lhr: any): PerformanceMetrics {
        const perfCategory = lhr.categories?.performance;
        const audits = lhr.audits || {};

        return {
            score: Math.round((perfCategory?.score || 0) * 100),
            firstContentfulPaint: this.getAuditNumericValue(audits, 'first-contentful-paint'),
            largestContentfulPaint: this.getAuditNumericValue(audits, 'largest-contentful-paint'),
            totalBlockingTime: this.getAuditNumericValue(audits, 'total-blocking-time'),
            cumulativeLayoutShift: this.getAuditNumericValue(audits, 'cumulative-layout-shift'),
            speedIndex: this.getAuditNumericValue(audits, 'speed-index'),
            timeToInteractive: this.getAuditNumericValue(audits, 'interactive'),
        };
    }

    /**
     * Extract accessibility metrics from Lighthouse result
     */
    private extractAccessibilityMetrics(lhr: any): AccessibilityMetrics {
        const a11yCategory = lhr.categories?.accessibility;
        const audits = lhr.audits || {};

        const issues: AccessibilityMetrics['issues'] = [];

        // Get failed accessibility audits
        Object.entries(audits).forEach(([id, audit]: [string, any]) => {
            if (
                audit.scoreDisplayMode === 'binary' &&
                audit.score === 0 &&
                audit.details?.items?.length > 0
            ) {
                issues.push({
                    id,
                    impact: this.mapImpact(audit.score),
                    description: audit.title || id,
                    helpUrl: audit.helpText,
                });
            }
        });

        return {
            score: Math.round((a11yCategory?.score || 0) * 100),
            issues,
        };
    }

    /**
     * Get numeric value from audit result
     */
    private getAuditNumericValue(audits: any, auditId: string): number {
        const audit = audits[auditId];
        if (!audit) return 0;
        return Math.round(audit.numericValue || 0);
    }

    /**
     * Map Lighthouse score to impact level
     */
    private mapImpact(score: number): 'critical' | 'serious' | 'moderate' | 'minor' {
        if (score === 0) return 'critical';
        if (score < 0.5) return 'serious';
        if (score < 0.9) return 'moderate';
        return 'minor';
    }

    /**
     * Close Chrome instance
     */
    async close(): Promise<void> {
        if (this.chrome) {
            await this.chrome.kill();
            this.chrome = null;
        }
    }
}

export default LighthouseService;
