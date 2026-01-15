/**
 * ResilienceTester Service
 * 
 * Verifies that the application works gracefully under poor network conditions.
 * Uses CDP to emulate "Regular 3G" speeds (The "Subway" Simulation).
 */

import { Page, CDPSession } from 'playwright';
import { logger } from '../utils/logger';

export interface ResilienceCheckResult {
    feature: string;
    passed: boolean;
    loadTime: number;
    skeletonDetected: boolean;
    error?: string;
}

export class ResilienceTester {

    /**
     * Test page load under "Regular 3G" conditions
     */
    async testSlowNetwork(page: Page, url: string): Promise<ResilienceCheckResult> {
        const feature = 'Network Resilience (3G)';
        let client: CDPSession | null = null;
        let skeletonDetected = false;
        const TIMEOUT = 15000;

        try {
            logger.info(`  🐌 Testing ${feature} on ${url}...`);

            // 1. Establish CDP Session
            client = await page.context().newCDPSession(page);

            // 2. The "Subway" Simulation (Enable Throttling)
            await this.simulateSlowNetwork(client);

            const startTime = Date.now();

            // 3. Navigation / Reload
            // We initiate reload and wait for load event with strict 15s timeout
            // Requirement asks to successfully render (Title exists)

            // Check for skeletons concurrently
            const skeletonPromise = this.checkForSkeletons(page);

            await page.reload({ waitUntil: 'domcontentloaded', timeout: TIMEOUT });

            // Ensure title exists (basic render check)
            const title = await page.title();
            if (!title) {
                throw new Error('Page title missing after reload');
            }

            skeletonDetected = await skeletonPromise;

            const duration = Date.now() - startTime;

            logger.info(`  ✅ Pass: Site handled 3G throttling gracefully in ${duration}ms`);

            if (skeletonDetected) {
                logger.info(`  ✅ Skeleton loading state detected`);
            }

            return {
                feature,
                passed: true,
                loadTime: duration,
                skeletonDetected
            };

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`  ❌ ${feature}: Fail: Timeout on 3G - ${errMsg}`);

            return {
                feature,
                passed: false,
                loadTime: TIMEOUT,
                skeletonDetected: false,
                error: errMsg
            };

        } finally {
            // 4. Reset Network
            if (client) {
                await this.resetNetwork(client);
                await client.detach();
            }
        }
    }

    /**
     * Throttles connection to "Regular 3G" (750kbps, 100ms latency)
     */
    private async simulateSlowNetwork(client: CDPSession): Promise<void> {
        await client.send('Network.enable');
        await client.send('Network.emulateNetworkConditions', {
            offline: false,
            latency: 100, // 100ms
            downloadThroughput: 750 * 1024 / 8, // 750 kbps
            uploadThroughput: 250 * 1024 / 8, // 250 kbps
            connectionType: 'cellular3g',
        });
    }

    /**
     * Restore full network speed
     */
    private async resetNetwork(client: CDPSession): Promise<void> {
        try {
            await client.send('Network.emulateNetworkConditions', {
                offline: false,
                latency: 0,
                downloadThroughput: -1,
                uploadThroughput: -1,
            });
            logger.debug('  🔄 Network throttling reset');
        } catch (e) {
            logger.warn(`Failed to reset network conditions: ${e}`);
        }
    }

    /**
     * Poll for skeleton elements
     */
    private async checkForSkeletons(page: Page): Promise<boolean> {
        const selectors = [
            '.skeleton',
            '[class*="skeleton"]',
            '.loading-shimmer',
            '.placeholder',
            '[aria-busy="true"]'
        ];

        // Poll for ~2 seconds
        for (let i = 0; i < 10; i++) {
            for (const sel of selectors) {
                try {
                    if (await page.isVisible(sel)) return true;
                } catch { /* ignore */ }
            }
            await page.waitForTimeout(200);
        }
        return false;
    }
}
