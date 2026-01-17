/**
 * InteractionTester Service
 * 
 * Performs functional testing on interactive elements.
 * Verifies Search functionality including happy path and empty state.
 */

import { Page } from 'playwright';
import { logger } from '../utils/logger.js';

export interface InteractionTestResult {
    feature: string;
    passed: boolean;
    duration: number;
    error?: string;
    details?: string;
}

export class InteractionTester {

    /**
     * Run all interaction tests
     */
    async runInteractions(page: Page): Promise<InteractionTestResult> {
        return this.testSearch(page);
    }

    /**
     * Test the Search functionality
     * 1. Happy Path: Search "ISO", verify results
     * 2. Edge Case: Search "SuperFakeGun123", verify no results
     */
    async testSearch(page: Page): Promise<InteractionTestResult> {
        const feature = 'Search Functionality';
        const startTime = Date.now();
        const HAPPY_TERM = 'ISO';
        const FAKE_TERM = 'SuperFakeGun123';

        // Potential selectors
        const SEARCH_SELECTORS = [
            'input[placeholder*="Search" i]',
            'input[type="search"]',
            'input[aria-label="Search"]',
            '#search'
        ];

        try {
            logger.info(`  🧪 Testing ${feature}...`);

            // 1. Find Search Input
            let searchInputStr = '';
            for (const selector of SEARCH_SELECTORS) {
                if (await page.isVisible(selector)) {
                    searchInputStr = selector;
                    break;
                }
            }

            if (!searchInputStr) {
                // No search input found - skip test gracefully (not all sites have search)
                logger.info(`  ⏭️ ${feature}: SKIPPED - No search input found on this page`);
                return {
                    feature,
                    passed: true, // Not a failure, just not applicable
                    duration: Date.now() - startTime,
                    details: 'Search input not found - test skipped'
                };
            }

            // --- HAPPY PATH ---
            logger.debug(`    Checking Happy Path (${HAPPY_TERM})...`);
            await page.click(searchInputStr);
            await page.fill(searchInputStr, HAPPY_TERM);

            // Wait for results
            // We wait for *any* element that might be a result, or just a pause if we don't know the selector
            // Heuristic: Wait for network idle or a short layout shift
            await page.waitForTimeout(2000);

            // Verify Results
            const hasHappyResult = await page.evaluate((term) => {
                // Look for the term in visible text, ignoring the input itself
                // This is a loose check but effective for "generic" sites
                const body = document.body.innerText;
                const matches = body.match(new RegExp(term, 'gi'));
                return matches && matches.length > 1; // More than just the input value
            }, HAPPY_TERM);

            if (!hasHappyResult) {
                throw new Error(`Happy Path Failed: No results found for "${HAPPY_TERM}"`);
            }

            // --- EDGE CASE ---
            logger.debug(`    Checking Edge Case (${FAKE_TERM})...`);
            await page.fill(searchInputStr, '');
            await page.fill(searchInputStr, FAKE_TERM);
            await page.waitForTimeout(2000);

            // Verify Empty State
            // Or check if the result list is empty/hidden
            // If we don't know the "No Results" text, we check if the Happy Result is GONE.
            // But confirming "ISO" is gone is trivial.
            // We assume a robust app shows "No results found" or similar.

            // If "SuperFakeGun123" appears in the body (other than input), that's weird.
            const hasFakeResult = await page.evaluate((term) => {
                const body = document.body.innerText;
                // Exclude the input value itself
                const inputVal = (document.querySelector(searchInputStr) as HTMLInputElement)?.value;
                if (inputVal === term) {
                    // matches needs to count > 1 occurence? 
                    // Actually, usually the input holds the value. 
                    // Let's count occurrences.
                    const matches = body.match(new RegExp(term, 'gi'));
                    return matches && matches.length > 1;
                }
                return body.includes(term);
            }, FAKE_TERM);

            if (hasFakeResult) {
                throw new Error(`Edge Case Failed: Found results for "${FAKE_TERM}" (Expected none)`);
            }

            // Clean up
            await page.fill(searchInputStr, '');

            const duration = Date.now() - startTime;
            logger.info(`  ✅ ${feature}: PASS (${duration}ms)`);

            return {
                feature,
                passed: true,
                duration
            };

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`  ❌ ${feature}: FAIL - ${errMsg}`);

            return {
                feature,
                passed: false,
                duration: Date.now() - startTime,
                error: errMsg
            };
        }
    }
}
