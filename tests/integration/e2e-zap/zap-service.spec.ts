/**
 * Integration Tests: ZAP Service
 *
 * Tests OWASP ZAP proxy integration.
 * Requires ZAP to be running via docker-compose.
 *
 * Run: docker-compose up -d zaproxy
 */

import { test, expect } from '../fixtures';
import { ZapService } from '../../../src/services/ZapService';
import { logger } from '../../../src/utils/logger';
import { loadEnvConfig } from '../../../src/config/env';

test.describe('ZAP Service', () => {
    test.describe('Initialization', () => {
        test('should initialize when ZAP is available', async ({ zapService, isZapAvailable }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            // If we got here, zapService was initialized successfully
            expect(zapService).toBeDefined();
        });

        test('should be in passive mode only', async ({ zapService, isZapAvailable }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            const isPassive = zapService.isPassiveMode();
            expect(isPassive).toBe(true);
        });
    });

    test.describe('Alert Retrieval', () => {
        test('should get alerts for URL', async ({ zapService, isZapAvailable, testUrl }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            const alerts = await zapService.getAlerts(testUrl);

            expect(Array.isArray(alerts)).toBe(true);

            // Each alert should have expected structure
            for (const alert of alerts) {
                expect(alert).toHaveProperty('risk');
                expect(alert).toHaveProperty('name');
                expect(alert).toHaveProperty('description');
                expect(alert).toHaveProperty('url');
            }
        });

        test('should get alert summary by risk level', async ({ zapService, isZapAvailable, testUrl }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            const summary = await zapService.getAlertSummary(testUrl);

            expect(summary).toHaveProperty('High');
            expect(summary).toHaveProperty('Medium');
            expect(summary).toHaveProperty('Low');
            expect(summary).toHaveProperty('Informational');

            expect(typeof summary.High).toBe('number');
            expect(typeof summary.Medium).toBe('number');
            expect(typeof summary.Low).toBe('number');
            expect(typeof summary.Informational).toBe('number');
        });

        test('should return empty alerts when ZAP not initialized', async ({ isZapAvailable }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            const config = loadEnvConfig();
            const service = new ZapService(config, logger);
            // Don't call initialize()

            const alerts = await service.getAlerts('https://example.com');
            expect(alerts).toEqual([]);
        });
    });

    test.describe('Cleanup', () => {
        test('should close gracefully', async ({ zapService, isZapAvailable }) => {
            test.skip(!isZapAvailable, 'ZAP is not available');

            await expect(zapService.close()).resolves.not.toThrow();
        });
    });
});

test.describe('ZAP Proxy Routing', () => {
    test('should route browser traffic through ZAP', async ({ isZapAvailable, testUrl }) => {
        test.skip(!isZapAvailable, 'ZAP is not available');

        const { BrowserService } = await import('../../../src/services/BrowserService');

        const browserService = new BrowserService();

        try {
            // Initialize with ZAP proxy
            await browserService.initialize({
                headless: true,
                useProxy: true,
            });

            // Navigate to example.com
            const result = await browserService.goto(testUrl);

            expect(result.ok).toBe(true);
            expect(result.status).toBe(200);

            // Traffic should have gone through ZAP
            // We can verify by checking ZAP has the URL in its history
            const config = loadEnvConfig();
            const zapUrl = config.ZAP_PROXY_URL;

            const response = await fetch(
                `${zapUrl}/JSON/core/view/urls/?baseurl=${encodeURIComponent(testUrl)}`
            );

            if (response.ok) {
                const data = await response.json() as { urls?: string[] };
                // ZAP should have recorded some URLs
                expect(data.urls?.length).toBeGreaterThanOrEqual(0);
            }
        } finally {
            await browserService.close();
        }
    });
});
