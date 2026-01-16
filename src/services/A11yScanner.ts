/**
 * A11yScanner Service
 * 
 * Performs deep accessibility testing using axe-core.
 * Flags ONLY Serious and Critical violations to reduce noise.
 */

import { Page } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import { logger } from '../utils/logger.js';

export interface A11yViolation {
    id: string;
    impact: string; // 'serious' | 'critical'
    description: string;
    helpUrl: string;
    nodes: number; // count of occurrences
    selector?: string; // example selector
    summary: string; // "Missing ARIA label on [selector]"
}

export interface A11yResult {
    url: string;
    score: number;
    violations: A11yViolation[];
    passed: boolean;
}

export class A11yScanner {

    /**
     * Scan the given page for accessibility issues
     * Filters strict: Only Serious and Critical.
     */
    async scan(page: Page, url: string): Promise<A11yResult> {
        const feature = 'Accessibility Scan';
        try {
            logger.info(`  ♿ Scanning ${feature} on ${url}...`);

            // Run Axe
            const results = await new AxeBuilder({ page })
                .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
                .analyze();

            // Filter Violations: Serious & Critical ONLY
            const relevantViolations = results.violations.filter(v =>
                v.impact === 'serious' || v.impact === 'critical'
            );

            // Map to our structure
            const violations: A11yViolation[] = relevantViolations.map(v => {
                const selector = v.nodes[0]?.target.join(' ') || '';
                return {
                    id: v.id,
                    impact: v.impact || 'unknown',
                    description: v.description,
                    helpUrl: v.helpUrl,
                    nodes: v.nodes.length,
                    selector,
                    summary: `${v.description} on ${selector ? '`' + selector + '`' : 'multiple elements'}`
                };
            });

            // Calc score (Starts at 100, heavy penalty for critical)
            let score = 100;
            violations.forEach(v => {
                if (v.impact === 'critical') score -= 15;
                else if (v.impact === 'serious') score -= 5;
            });
            score = Math.max(0, score);

            const passed = violations.length === 0;

            if (!passed) {
                logger.warn(`  ⚠️ Found ${violations.length} Critical/Serious A11y violations (Score: ${score})`);
                // Log top 3 for immediate visibility
                violations.slice(0, 3).forEach(v => {
                    logger.debug(`    - [${v.impact}] ${v.summary}`);
                });
            } else {
                logger.info(`  ✅ Accessibility passed (Score: 100)`);
            }

            return {
                url,
                score,
                violations,
                passed
            };

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`  ❌ ${feature}: FAIL - ${errMsg}`);

            return {
                url,
                score: 0,
                violations: [],
                passed: false
            };
        }
    }
}
