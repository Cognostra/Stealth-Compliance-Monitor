// @ts-nocheck - Playwright fixture types don't resolve correctly with TypeScript
/**
 * Integration Tests: Lighthouse Service
 *
 * Tests Lighthouse performance and accessibility auditing.
 * Uses example.com as a safe public target.
 */

import { test, expect } from '../fixtures/index.js';
import { LighthouseService } from '../../../src/services/LighthouseService.js';
import { logger } from '../../../src/utils/logger.js';

test.describe('Lighthouse Service', () => {
    test.describe('Audit Execution', () => {
        test('should run lighthouse audit on example.com', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            try {
                const result = await service.runAudit(testUrl);

                // Performance metrics
                expect(result.performance).toBeDefined();
                expect(result.performance.score).toBeGreaterThanOrEqual(0);
                expect(result.performance.score).toBeLessThanOrEqual(100);

                // Core Web Vitals should be present
                expect(result.performance.firstContentfulPaint).toBeGreaterThanOrEqual(0);
                expect(result.performance.largestContentfulPaint).toBeGreaterThanOrEqual(0);
                expect(result.performance.totalBlockingTime).toBeGreaterThanOrEqual(0);
                expect(result.performance.cumulativeLayoutShift).toBeGreaterThanOrEqual(0);
                expect(result.performance.speedIndex).toBeGreaterThanOrEqual(0);

                // Accessibility metrics
                expect(result.accessibility).toBeDefined();
                expect(result.accessibility.score).toBeGreaterThanOrEqual(0);
                expect(result.accessibility.score).toBeLessThanOrEqual(100);
                expect(Array.isArray(result.accessibility.issues)).toBe(true);
            } finally {
                await service.close();
            }
        }, 120000); // 2 minute timeout for Lighthouse

        test('should report performance score', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            try {
                const result = await service.runAudit(testUrl);

                // Example.com should have a good performance score
                expect(result.performance.score).toBeGreaterThanOrEqual(50);
            } finally {
                await service.close();
            }
        }, 120000);

        test('should report accessibility score', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            try {
                const result = await service.runAudit(testUrl);

                // Example.com should have a good accessibility score
                expect(result.accessibility.score).toBeGreaterThanOrEqual(80);
            } finally {
                await service.close();
            }
        }, 120000);
    });

    test.describe('Metrics Extraction', () => {
        test('should extract all performance metrics', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            try {
                const result = await service.runAudit(testUrl);

                // All metrics should be numbers
                expect(typeof result.performance.score).toBe('number');
                expect(typeof result.performance.firstContentfulPaint).toBe('number');
                expect(typeof result.performance.largestContentfulPaint).toBe('number');
                expect(typeof result.performance.totalBlockingTime).toBe('number');
                expect(typeof result.performance.cumulativeLayoutShift).toBe('number');
                expect(typeof result.performance.speedIndex).toBe('number');
                expect(typeof result.performance.timeToInteractive).toBe('number');
            } finally {
                await service.close();
            }
        }, 120000);
    });

    test.describe('Cleanup', () => {
        test('should close Chrome instance after audit', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            await service.runAudit(testUrl);

            // Should not throw when closing
            await expect(service.close()).resolves.not.toThrow();
        }, 120000);

        test('should handle multiple close calls gracefully', async ({ testUrl }) => {
            const service = new LighthouseService(logger);

            await service.runAudit(testUrl);

            // Multiple close calls should not throw
            await service.close();
            await service.close();
        }, 120000);
    });
});
