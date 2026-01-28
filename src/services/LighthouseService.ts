/**
 * Lighthouse Service
 * Performance and accessibility auditing
 */

import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import { PerformanceMetrics, AccessibilityMetrics, Logger, PerformanceBudget } from '../types/index.js';
import { PerformanceBaseline, LighthouseScores } from '../v3/services/PerformanceBaseline.js';

export class LighthouseService {
    private readonly logger: Logger;
    private chrome: chromeLauncher.LaunchedChrome | null = null;

    constructor(logger: Logger) {
        this.logger = logger;
    }

    /**
     * Run Lighthouse audit on URL
     */
    async runAudit(url: string, options?: {
        useBaseline?: boolean;
        budget?: PerformanceBudget;
    }): Promise<{
        performance: PerformanceMetrics;
        accessibility: AccessibilityMetrics;
        baselineComparison?: unknown;
        budgetExceeded?: boolean;
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

            const lhr = result.lhr as unknown as LighthouseRunResult;

            // Extract performance metrics
            const performance = this.extractPerformanceMetrics(lhr);

            // Extract accessibility metrics
            const accessibility = this.extractAccessibilityMetrics(lhr);

            this.logger.info('Lighthouse audit completed', {
                performanceScore: performance.score,
                accessibilityScore: accessibility.score,
            });

            // Check budgets
            let budgetExceeded = false;
            if (options?.budget) {
                budgetExceeded = this.checkBudget(performance, options.budget);
            }

            // Check baseline
            let baselineComparison;
            if (options?.useBaseline) {
                try {
                    const baselineService = new PerformanceBaseline();
                    if (baselineService.load()) {
                        const currentScores: LighthouseScores = {
                            performance: performance.score || 0,
                            accessibility: accessibility.score || 0,
                            bestPractices: (lhr.categories?.['best-practices']?.score || 0) * 100,
                            seo: (lhr.categories?.seo?.score || 0) * 100,
                            pwa: (lhr.categories?.pwa?.score || 0) * 100,
                        };
                        
                        baselineComparison = baselineService.compare(url, currentScores);
                        
                        if (baselineComparison.overallStatus === 'regressed') {
                            this.logger.warn(`⚠️ Performance regression detected for ${url}`);
                        }
                    }
                } catch (err) {
                    this.logger.warn(`Failed to process baseline: ${err}`);
                }
            }

            return { performance, accessibility, baselineComparison, budgetExceeded };
        } finally {
            await this.close();
        }
    }

    /**
     * Check metrics against budget
     */
    private checkBudget(metrics: PerformanceMetrics, budget: PerformanceBudget): boolean {
        const violations: string[] = [];
        
        if (metrics.score < budget.minScore) {
            violations.push(`Score ${metrics.score} < ${budget.minScore}`);
        }
        if (budget.maxLCP && metrics.largestContentfulPaint > budget.maxLCP) {
            violations.push(`LCP ${metrics.largestContentfulPaint}ms > ${budget.maxLCP}ms`);
        }
        if (budget.maxCLS && metrics.cumulativeLayoutShift > budget.maxCLS) {
            violations.push(`CLS ${metrics.cumulativeLayoutShift} > ${budget.maxCLS}`);
        }
        if (budget.maxTBT && metrics.totalBlockingTime > budget.maxTBT) {
            violations.push(`TBT ${metrics.totalBlockingTime}ms > ${budget.maxTBT}ms`);
        }

        if (violations.length > 0) {
            this.logger.warn('Performance budget exceeded:', { violations });
            return true;
        }
        return false;
    }

    /**
     * Extract performance metrics from Lighthouse result
     */
    private extractPerformanceMetrics(lhr: LighthouseRunResult): PerformanceMetrics {
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
    private extractAccessibilityMetrics(lhr: LighthouseRunResult): AccessibilityMetrics {
        const a11yCategory = lhr.categories?.accessibility;
        const audits = lhr.audits || {};

        const issues: AccessibilityMetrics['issues'] = [];

        // Get failed accessibility audits
        Object.entries(audits).forEach(([id, audit]) => {
            if (
                audit.scoreDisplayMode === 'binary' &&
                audit.score === 0 &&
                (audit.details?.items?.length ?? 0) > 0
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
    private getAuditNumericValue(audits: Record<string, LighthouseAuditResult>, auditId: string): number {
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
        if (!this.chrome) {
            return;
        }

        try {
            await this.chrome.kill();
        } catch (error) {
            this.logger.warn('Failed to close Lighthouse Chrome instance', { error });
        } finally {
            this.chrome = null;
        }
    }
}

type LighthouseAuditResult = {
    scoreDisplayMode?: string;
    score?: number | null;
    details?: { items?: unknown[] };
    title?: string;
    helpText?: string;
    numericValue?: number;
};

type LighthouseRunResult = {
    categories?: {
        performance?: { score?: number | null };
        accessibility?: { score?: number | null };
        'best-practices'?: { score?: number | null };
        seo?: { score?: number | null };
        pwa?: { score?: number | null };
    };
    audits?: Record<string, LighthouseAuditResult>;
};

export default LighthouseService;
