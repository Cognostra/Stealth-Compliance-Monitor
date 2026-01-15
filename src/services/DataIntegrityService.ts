/**
 * DataIntegrityService
 * 
 * Performs "Deep Logical Testing" on key pages to ensure complex data structures
 * render correctly.
 * 
 * Focus:
 * - Validating Meta Loadouts have exactly 5 attachments
 * - Ensuring weapon names match page titles
 * - Detecting "partial loading" states where frames load but data is missing
 */

import { BrowserService } from './BrowserService';
import { getConfig, EnvConfig } from '../config/env';
import { logger } from '../utils/logger';

export interface IntegrityTestResult {
    url: string;
    passed: boolean;
    checkType: 'loadout_completion' | 'weapon_match' | 'other';
    details: string;
    attachmentsFound?: number;
    expectedAttachments?: number;
    screenshotPath?: string;
    duration: number;
}

export interface IntegritySessionResult {
    testsRun: number;
    passed: number;
    failed: number;
    results: IntegrityTestResult[];
    timestamp: string;
}

/**
 * Configuration for the integrity checks
 */
const INTEGRITY_CONFIG = {
    // Selector for individual attachment slots/cards in a loadout
    // Adjust this based on the actual DOM structure of loadout.app
    attachmentSelector: '.attachment-slot, .item-card, .attachment-item, [data-testid="attachment"], .loadout-grid > div',

    // Selector for the weapon name on the page
    weaponNameSelector: 'h1, .weapon-title, .loadout-title',

    // Specific high-traffic URLs to test (relative to base URL)
    // We rely on crawler-discovered URLs for dynamic pages
    // Note: /meta was removed as it's treated as a username on loadout.app
    testPaths: [
        // Intentionally empty - relies on discovered URLs from crawler
    ],

    expectedAttachments: 5
};

export class DataIntegrityService {
    private readonly browserService: BrowserService;
    private readonly config: EnvConfig;

    constructor(browserService: BrowserService) {
        this.browserService = browserService;
        this.config = getConfig();
    }

    /**
     * Run the full suite of data integrity checks
     */
    async runIntegrityChecks(discoveredUrls?: string[]): Promise<IntegritySessionResult> {
        logger.info('═'.repeat(50));
        logger.info('DATA INTEGRITY SERVICE - Deep Logical Testing');
        logger.info('═'.repeat(50));

        const results: IntegrityTestResult[] = [];
        const startTime = Date.now();

        try {
            // 1. Identify Target URLs
            // We prefer URLs passed from the crawler (high value), specifically looking for 'loadout' or 'weapon' pages
            // If none provided, we default to the configured test paths
            const targets = this.identifyTargets(discoveredUrls);

            logger.info(`Identified ${targets.length} targets for deep integrity testing`);

            // 2. Run Checks on each target
            for (const url of targets) {
                logger.info(`Testing integrity for: ${url}`);

                // Navigate
                await this.browserService.goto(url);

                // Check 1: Attachment Count (The "5 Attachments" Rule)
                // Only run this if the URL looks like a specific loadout page
                if (this.isLoadoutPage(url)) {
                    const loadoutResult = await this.verifyLoadoutIntegrity(url);
                    results.push(loadoutResult);
                    this.logResult(loadoutResult);
                }

                // Check 2: Header/Title Match
                const matchResult = await this.verifyHeaderMatch(url);
                results.push(matchResult);
                this.logResult(matchResult);
            }

        } catch (error) {
            logger.error(`Integrity check failed: ${error}`);
        }

        const passed = results.filter(r => r.passed).length;
        const failed = results.filter(r => !r.passed).length;

        logger.info('');
        logger.info(`Integrity Checks Complete: ${passed} Passed, ${failed} Failed`);

        return {
            testsRun: results.length,
            passed,
            failed,
            results,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Verify that a loadout page renders exactly 5 attachments
     */
    private async verifyLoadoutIntegrity(url: string): Promise<IntegrityTestResult> {
        const start = Date.now();

        // Attempt to count attachments using multiple potential selectors if one fails?
        // For now, we rely on the specific CSS selector configuration.
        // In a real scenario, we might need to be more "smart" or have strict selectors.

        // We look for elements that represent an attachment.
        // NOTE: This can be tricky if the DOM uses shadow DOM or lazy loading.
        // BrowserService.countElements uses standard querySelectorAll.

        const count = await this.browserService.countElements(INTEGRITY_CONFIG.attachmentSelector);

        const passed = count === INTEGRITY_CONFIG.expectedAttachments;
        let screenshotPath: string | undefined;

        if (!passed) {
            // Capture failure evidence
            const safeName = url.split('/').pop() || 'loadout';
            const screenshot = await this.browserService.screenshot(`integrity-fail-attachments-${safeName}`);
            screenshotPath = screenshot.path;
        }

        return {
            url,
            passed,
            checkType: 'loadout_completion',
            attachmentsFound: count,
            expectedAttachments: INTEGRITY_CONFIG.expectedAttachments,
            details: passed
                ? `Integrity Verified: Found exactly ${count} attachments.`
                : `Data Integrity Error: Incomplete Build. Expected 5 attachments, found ${count}.`,
            screenshotPath,
            duration: Date.now() - start
        };
    }

    /**
     * Verify transparency: Page Title matches H1/Weapon Name
     */
    private async verifyHeaderMatch(url: string): Promise<IntegrityTestResult> {
        const start = Date.now();

        const pageTitle = await this.browserService.getTitle();
        const h1Text = await this.browserService.getText(INTEGRITY_CONFIG.weaponNameSelector);

        // Loose matching: The H1 text should be contained in the Title or vice versa
        const cleanTitle = (pageTitle || '').toLowerCase().trim();
        const cleanH1 = (h1Text || '').toLowerCase().trim();

        const passed = cleanTitle.includes(cleanH1) || cleanH1.includes(cleanTitle);

        let screenshotPath: string | undefined;
        if (!passed) {
            const safeName = url.split('/').pop() || 'page';
            const screenshot = await this.browserService.screenshot(`integrity-fail-header-${safeName}`);
            screenshotPath = screenshot.path;
        }

        return {
            url,
            passed,
            checkType: 'weapon_match',
            details: passed
                ? `Text Match Verified: Title "${cleanTitle}" matches Header "${cleanH1}"`
                : `Content Mismatch: Title "${cleanTitle}" does not match Header "${cleanH1}"`,
            screenshotPath,
            duration: Date.now() - start
        };
    }

    /**
     * Identify which URLs to test
     * Prioritizes specific loadout pages found during crawl, or defaults to specific targets
     */
    private identifyTargets(discoveredUrls: string[] = []): string[] {
        const uniqueParams = new Set<string>();
        const targets: string[] = [];

        // 1. Add manual high-priority paths
        INTEGRITY_CONFIG.testPaths.forEach(path => {
            targets.push(`${this.config.LIVE_URL}${path}`);
        });

        // 2. Filter discovered URLs for "deep" loadout pages
        // We look for URLs that likely actually contain a loadout ID, e.g. /loadouts/123 or /weapon/m4/meta
        const loadoutPatterns = [
            /\/loadouts\/\d+/,      // /loadouts/123
            /\/weapon\/[\w-]+\/[\w-]+/ // /weapon/m4/meta
        ];

        const deepPages = discoveredUrls.filter(url => {
            return loadoutPatterns.some(pattern => pattern.test(url));
        });

        // Limit to 3 dynamic pages to keep test fast
        deepPages.slice(0, 3).forEach(url => targets.push(url));

        // Remove duplicates
        return [...new Set(targets)];
    }

    /**
     * Heuristic to determine if a URL is likely a loadout page
     */
    private isLoadoutPage(url: string): boolean {
        return url.includes('/loadout') || url.includes('/build') || url.includes('/weapon/');
    }

    private logResult(result: IntegrityTestResult) {
        if (result.passed) {
            logger.info(`  ✓ ${result.details}`);
        } else {
            logger.error(`  ✗ ${result.details}`);
            if (result.screenshotPath) {
                logger.info(`    Evidence: ${result.screenshotPath}`);
            }
        }
    }
}
