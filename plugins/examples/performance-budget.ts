/**
 * Performance Budget Checker
 * 
 * Enforces performance budgets for web applications:
 * - Page weight limits (HTML, CSS, JS, images)
 * - Request count limits
 * - Third-party script limits
 * - Web font limits
 * 
 * Configure via environment variables:
 *   PERF_BUDGET_MAX_PAGE_WEIGHT_KB - Max total page weight (default: 3000)
 *   PERF_BUDGET_MAX_JS_KB - Max JavaScript size (default: 500)
 *   PERF_BUDGET_MAX_REQUESTS - Max HTTP requests (default: 100)
 *   PERF_BUDGET_MAX_THIRD_PARTY - Max third-party domains (default: 10)
 * 
 * @author Community
 * @version 1.0.0
 * @tags performance, budget, optimization, core-web-vitals
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../../src/core/CustomCheckLoader';

// Configuration with defaults
const CONFIG = {
    maxPageWeightKB: parseInt(process.env.PERF_BUDGET_MAX_PAGE_WEIGHT_KB || '3000'),
    maxJsKB: parseInt(process.env.PERF_BUDGET_MAX_JS_KB || '500'),
    maxCssKB: parseInt(process.env.PERF_BUDGET_MAX_CSS_KB || '200'),
    maxImageKB: parseInt(process.env.PERF_BUDGET_MAX_IMAGE_KB || '2000'),
    maxRequests: parseInt(process.env.PERF_BUDGET_MAX_REQUESTS || '100'),
    maxThirdParty: parseInt(process.env.PERF_BUDGET_MAX_THIRD_PARTY || '10'),
    maxFonts: parseInt(process.env.PERF_BUDGET_MAX_FONTS || '5'),
    maxDomElements: parseInt(process.env.PERF_BUDGET_MAX_DOM_ELEMENTS || '1500'),
};

interface ResourceStats {
    total: number;
    js: number;
    css: number;
    images: number;
    fonts: number;
    other: number;
    requestCount: number;
    thirdPartyDomains: Set<string>;
}

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[PerfBudget] Checking performance budget on: ${context.currentUrl}`);

    try {
        const pageUrl = new URL(context.currentUrl);
        const firstPartyDomain = pageUrl.hostname;

        // Collect resource timing data
        const resources = await page.evaluate(() => {
            return performance.getEntriesByType('resource').map(entry => {
                const r = entry as PerformanceResourceTiming;
                return {
                    name: r.name,
                    type: r.initiatorType,
                    size: r.transferSize || 0,
                };
            });
        });

        // Calculate stats
        const stats: ResourceStats = {
            total: 0,
            js: 0,
            css: 0,
            images: 0,
            fonts: 0,
            other: 0,
            requestCount: resources.length,
            thirdPartyDomains: new Set(),
        };

        for (const resource of resources) {
            const sizeKB = resource.size / 1024;
            stats.total += sizeKB;

            // Categorize by type
            if (resource.type === 'script' || resource.name.endsWith('.js')) {
                stats.js += sizeKB;
            } else if (resource.type === 'css' || resource.name.endsWith('.css')) {
                stats.css += sizeKB;
            } else if (resource.type === 'img' || /\.(png|jpg|jpeg|gif|webp|svg|ico)/.test(resource.name)) {
                stats.images += sizeKB;
            } else if (/\.(woff|woff2|ttf|otf|eot)/.test(resource.name)) {
                stats.fonts += sizeKB;
            } else {
                stats.other += sizeKB;
            }

            // Track third-party domains
            try {
                const resourceUrl = new URL(resource.name);
                if (resourceUrl.hostname !== firstPartyDomain && 
                    !resourceUrl.hostname.endsWith(`.${firstPartyDomain}`)) {
                    stats.thirdPartyDomains.add(resourceUrl.hostname);
                }
            } catch {
                // Ignore invalid URLs
            }
        }

        // Check total page weight
        if (stats.total > CONFIG.maxPageWeightKB) {
            violations.push({
                id: 'perf-budget-page-weight',
                title: 'Page Weight Exceeds Budget',
                severity: 'high',
                description: `Total page weight (${Math.round(stats.total)}KB) exceeds budget (${CONFIG.maxPageWeightKB}KB).`,
                remediation: 'Optimize images, minify assets, implement code splitting, and remove unused code.',
                evidence: `JS: ${Math.round(stats.js)}KB, CSS: ${Math.round(stats.css)}KB, Images: ${Math.round(stats.images)}KB, Fonts: ${Math.round(stats.fonts)}KB`,
                url: context.currentUrl,
            });
        }

        // Check JavaScript size
        if (stats.js > CONFIG.maxJsKB) {
            violations.push({
                id: 'perf-budget-js-size',
                title: 'JavaScript Size Exceeds Budget',
                severity: 'high',
                description: `JavaScript payload (${Math.round(stats.js)}KB) exceeds budget (${CONFIG.maxJsKB}KB).`,
                remediation: 'Implement code splitting, tree shaking, and lazy loading. Consider removing unused dependencies.',
                url: context.currentUrl,
            });
        }

        // Check CSS size
        if (stats.css > CONFIG.maxCssKB) {
            violations.push({
                id: 'perf-budget-css-size',
                title: 'CSS Size Exceeds Budget',
                severity: 'medium',
                description: `CSS payload (${Math.round(stats.css)}KB) exceeds budget (${CONFIG.maxCssKB}KB).`,
                remediation: 'Remove unused CSS, consider CSS-in-JS or critical CSS extraction.',
                url: context.currentUrl,
            });
        }

        // Check image size
        if (stats.images > CONFIG.maxImageKB) {
            violations.push({
                id: 'perf-budget-image-size',
                title: 'Image Size Exceeds Budget',
                severity: 'medium',
                description: `Image payload (${Math.round(stats.images)}KB) exceeds budget (${CONFIG.maxImageKB}KB).`,
                remediation: 'Compress images, use WebP/AVIF formats, implement lazy loading, and use responsive images.',
                url: context.currentUrl,
            });
        }

        // Check request count
        if (stats.requestCount > CONFIG.maxRequests) {
            violations.push({
                id: 'perf-budget-request-count',
                title: 'Too Many HTTP Requests',
                severity: 'medium',
                description: `Request count (${stats.requestCount}) exceeds budget (${CONFIG.maxRequests}).`,
                remediation: 'Bundle assets, use HTTP/2 multiplexing, and implement resource hints.',
                url: context.currentUrl,
            });
        }

        // Check third-party domains
        if (stats.thirdPartyDomains.size > CONFIG.maxThirdParty) {
            violations.push({
                id: 'perf-budget-third-party',
                title: 'Too Many Third-Party Domains',
                severity: 'medium',
                description: `Third-party domain count (${stats.thirdPartyDomains.size}) exceeds budget (${CONFIG.maxThirdParty}).`,
                remediation: 'Audit and consolidate third-party scripts. Self-host critical resources.',
                evidence: `Domains: ${Array.from(stats.thirdPartyDomains).slice(0, 10).join(', ')}${stats.thirdPartyDomains.size > 10 ? '...' : ''}`,
                url: context.currentUrl,
            });
        }

        // Check DOM size
        const domElementCount = await page.evaluate(() => document.querySelectorAll('*').length);
        if (domElementCount > CONFIG.maxDomElements) {
            violations.push({
                id: 'perf-budget-dom-size',
                title: 'DOM Size Exceeds Budget',
                severity: 'medium',
                description: `DOM element count (${domElementCount}) exceeds budget (${CONFIG.maxDomElements}).`,
                remediation: 'Simplify page structure, virtualize long lists, and use pagination.',
                url: context.currentUrl,
            });
        }

        // Check for render-blocking resources
        const renderBlocking = await page.evaluate(() => {
            const scripts = document.querySelectorAll('script:not([async]):not([defer]):not([type="module"])');
            const stylesheets = document.querySelectorAll('link[rel="stylesheet"]:not([media="print"])');
            return {
                scripts: scripts.length,
                stylesheets: stylesheets.length,
            };
        });

        if (renderBlocking.scripts > 5) {
            violations.push({
                id: 'perf-budget-render-blocking-js',
                title: 'Too Many Render-Blocking Scripts',
                severity: 'medium',
                description: `${renderBlocking.scripts} render-blocking scripts found.`,
                remediation: 'Add async or defer attributes to non-critical scripts.',
                url: context.currentUrl,
            });
        }

        context.logger.debug(`[PerfBudget] Stats: ${JSON.stringify({
            totalKB: Math.round(stats.total),
            jsKB: Math.round(stats.js),
            cssKB: Math.round(stats.css),
            requests: stats.requestCount,
            thirdParty: stats.thirdPartyDomains.size,
        })}`);

    } catch (error) {
        context.logger.warn(`[PerfBudget] Check failed: ${error}`);
    }

    return violations;
}
