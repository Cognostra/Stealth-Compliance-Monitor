/**
 * Integration Tests: Configuration Loading
 *
 * Tests the configuration system for proper loading,
 * validation, and error handling.
 */

import { test, expect } from '../fixtures/index.js';
import { loadEnvConfig, resetConfig, getConfig } from '../../../src/config/env.js';

test.describe('Configuration System', () => {
    test.beforeEach(() => {
        resetConfig();
    });

    test('should load configuration from environment', async ({ testConfig }) => {
        expect(testConfig).toBeDefined();
        expect(testConfig.LIVE_URL).toBeDefined();
        expect(testConfig.LIVE_URL).toMatch(/^https?:\/\//);
    });

    test('should have required environment variables', async ({ testConfig }) => {
        // These should be set in test environment
        expect(testConfig.LIVE_URL).toBeTruthy();
        expect(testConfig.TEST_EMAIL).toBeTruthy();
        expect(testConfig.TEST_PASSWORD).toBeTruthy();
    });

    test('should have sensible default delays', async ({ testConfig }) => {
        expect(testConfig.MIN_DELAY_MS).toBeGreaterThanOrEqual(0);
        expect(testConfig.MAX_DELAY_MS).toBeGreaterThanOrEqual(testConfig.MIN_DELAY_MS);
    });

    test('should have valid ZAP proxy URL', async ({ testConfig }) => {
        if (testConfig.ZAP_PROXY_URL) {
            expect(testConfig.ZAP_PROXY_URL).toMatch(/^https?:\/\//);
        }
    });

    test('should return same instance on subsequent getConfig calls', async () => {
        const config1 = getConfig();
        const config2 = getConfig();
        expect(config1).toBe(config2);
    });

    test('should return new instance after reset', async () => {
        const config1 = getConfig();
        resetConfig();
        const config2 = getConfig();
        // Different object but same values
        expect(config1).not.toBe(config2);
        expect(config1.LIVE_URL).toBe(config2.LIVE_URL);
    });
});
