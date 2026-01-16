/**
 * Playwright Test Fixtures
 *
 * Custom fixtures for integration testing the compliance monitor.
 * These fixtures provide pre-configured service instances for tests.
 */

import { test as base, expect } from '@playwright/test';
import { BrowserService } from '../../../src/services/BrowserService';
import { ZapService } from '../../../src/services/ZapService';
import { LighthouseService } from '../../../src/services/LighthouseService';
import { SecretScanner } from '../../../src/services/SecretScanner';
import { NetworkSpy } from '../../../src/services/NetworkSpy';
import { A11yScanner } from '../../../src/services/A11yScanner';
import { loadEnvConfig, resetConfig, EnvConfig } from '../../../src/config/env';
import { logger } from '../../../src/utils/logger';

/**
 * Test fixture types
 */
export interface TestFixtures {
    // Services
    browserService: BrowserService;
    zapService: ZapService;
    lighthouseService: LighthouseService;
    secretScanner: SecretScanner;
    networkSpy: NetworkSpy;
    a11yScanner: A11yScanner;

    // Config
    testConfig: EnvConfig;

    // Utilities
    testUrl: string;
    isZapAvailable: boolean;
}

/**
 * Worker-scoped fixtures (shared across tests in a worker)
 */
export interface WorkerFixtures {
    zapAvailability: boolean;
}

/**
 * Create extended test with custom fixtures
 */
export const test = base.extend<TestFixtures, WorkerFixtures>({
    // Worker-scoped: Check ZAP availability once per worker
    zapAvailability: [async ({}, use) => {
        const zapUrl = process.env.ZAP_PROXY_URL || 'http://localhost:8080';
        let available = false;

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(`${zapUrl}/JSON/core/view/version/`, {
                signal: controller.signal,
            });
            clearTimeout(timeout);
            available = response.ok;
        } catch {
            available = false;
        }

        await use(available);
    }, { scope: 'worker' }],

    // Test config - reset before each test
    testConfig: async ({}, use) => {
        resetConfig();
        const config = loadEnvConfig();
        await use(config);
    },

    // Test URL - defaults to example.com for safety
    testUrl: async ({}, use) => {
        const url = process.env.TEST_BASE_URL || 'https://example.com';
        await use(url);
    },

    // Is ZAP available for this test
    isZapAvailable: async ({ zapAvailability }, use) => {
        await use(zapAvailability);
    },

    // BrowserService fixture
    browserService: async ({ testConfig }, use) => {
        const service = new BrowserService();

        // Initialize with test-friendly settings (no proxy for basic tests)
        await service.initialize({
            headless: true,
            useProxy: false,
        });

        await use(service);

        // Cleanup
        await service.close();
    },

    // ZapService fixture (requires ZAP to be running)
    zapService: async ({ testConfig, isZapAvailable }, use, testInfo) => {
        if (!isZapAvailable) {
            testInfo.skip(true, 'ZAP is not available');
        }

        const service = new ZapService(testConfig, logger);
        await service.initialize();

        await use(service);

        await service.close();
    },

    // LighthouseService fixture
    lighthouseService: async ({}, use) => {
        const service = new LighthouseService(logger);

        await use(service);

        await service.close();
    },

    // SecretScanner fixture
    secretScanner: async ({}, use) => {
        const scanner = new SecretScanner();
        await use(scanner);
        scanner.clear();
    },

    // NetworkSpy fixture
    networkSpy: async ({}, use) => {
        const spy = new NetworkSpy();
        await use(spy);
        spy.clear();
    },

    // A11yScanner fixture
    a11yScanner: async ({}, use) => {
        const scanner = new A11yScanner();
        await use(scanner);
    },
});

/**
 * Re-export expect for convenience
 */
export { expect };

/**
 * Test skip helper for conditional tests
 */
export function skipIfNoZap(test: typeof base, isAvailable: boolean) {
    test.skip(!isAvailable, 'ZAP proxy is not available');
}

/**
 * Test skip helper for CI environment
 */
export function skipIfCI(test: typeof base) {
    test.skip(!!process.env.CI, 'Skipped in CI environment');
}
