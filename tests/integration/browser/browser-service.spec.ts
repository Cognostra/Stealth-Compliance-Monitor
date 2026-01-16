/**
 * Integration Tests: Browser Service
 *
 * Tests browser initialization, navigation, and interaction.
 * Uses example.com as a safe public target.
 */

import { test, expect } from '../fixtures';
import { BrowserService } from '../../../src/services/BrowserService';

test.describe('Browser Service', () => {
    test.describe('Initialization', () => {
        test('should initialize browser successfully', async ({ browserService }) => {
            expect(browserService.isReady()).toBe(true);
        });

        test('should have page available after init', async ({ browserService }) => {
            expect(browserService.getPage()).not.toBeNull();
        });

        test('should have context available after init', async ({ browserService }) => {
            expect(browserService.getContext()).not.toBeNull();
        });

        test('should register default scanners', async ({ browserService }) => {
            const registry = browserService.getRegistry();
            expect(registry.count).toBeGreaterThanOrEqual(5);

            const names = registry.getScannerNames();
            expect(names).toContain('NetworkSpy');
            expect(names).toContain('SecretScanner');
            expect(names).toContain('ConsoleMonitor');
        });
    });

    test.describe('Navigation', () => {
        test('should navigate to example.com', async ({ browserService, testUrl }) => {
            const result = await browserService.goto(testUrl);

            expect(result.ok).toBe(true);
            expect(result.status).toBe(200);
            expect(result.url).toContain('example.com');
        });

        test('should return timing information', async ({ browserService, testUrl }) => {
            const result = await browserService.goto(testUrl);

            expect(result.timing.duration).toBeGreaterThan(0);
            expect(result.timing.started).toBeLessThan(result.timing.finished);
        });

        test('should capture response headers', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const headers = browserService.getLastResponseHeaders();
            expect(headers.size).toBeGreaterThan(0);
        });

        test('should get current URL after navigation', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const currentUrl = browserService.getCurrentUrl();
            expect(currentUrl).toContain('example.com');
        });

        test('should get page title', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const title = await browserService.getTitle();
            expect(title).toBeTruthy();
            expect(title.length).toBeGreaterThan(0);
        });
    });

    test.describe('Element Interaction', () => {
        test('should check if element exists', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            // Example.com has a div with a p tag
            const exists = await browserService.exists('body');
            expect(exists).toBe(true);

            const notExists = await browserService.exists('#nonexistent-element');
            expect(notExists).toBe(false);
        });

        test('should get element text', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const text = await browserService.getText('body');
            expect(text).toBeTruthy();
            expect(text?.length).toBeGreaterThan(0);
        });

        test('should get all links from page', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const links = await browserService.getAllLinks();
            // Example.com has at least one link
            expect(links.length).toBeGreaterThan(0);
            expect(links[0]).toMatch(/^https?:\/\//);
        });

        test('should count elements', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const count = await browserService.countElements('p');
            expect(count).toBeGreaterThanOrEqual(1);
        });

        test('should wait for selector', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const found = await browserService.waitForSelector('body', 5000);
            expect(found).toBe(true);

            const notFound = await browserService.waitForSelector('#nonexistent', 1000);
            expect(notFound).toBe(false);
        });
    });

    test.describe('Screenshots', () => {
        test('should take screenshot', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const result = await browserService.screenshot('test-screenshot');

            expect(result.path).toContain('test-screenshot');
            expect(result.timestamp).toBeGreaterThan(0);
        });
    });

    test.describe('Multi-page Support', () => {
        test('should create new pages for parallel execution', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const newPage = await browserService.createNewPage();
            expect(newPage).not.toBeNull();

            await browserService.closePage(newPage);
        });
    });

    test.describe('Scanner Data Collection', () => {
        test('should collect network incidents', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const incidents = browserService.getNetworkIncidents();
            expect(Array.isArray(incidents)).toBe(true);
        });

        test('should collect console errors', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const errors = browserService.getConsoleErrors();
            expect(Array.isArray(errors)).toBe(true);
        });

        test('should collect leaked secrets', async ({ browserService, testUrl }) => {
            await browserService.goto(testUrl);

            const secrets = browserService.getLeakedSecrets();
            expect(Array.isArray(secrets)).toBe(true);
        });
    });

    test.describe('Cleanup', () => {
        test('should close browser properly', async () => {
            const service = new BrowserService();
            await service.initialize({ headless: true, useProxy: false });

            expect(service.isReady()).toBe(true);

            await service.close();

            expect(service.isReady()).toBe(false);
        });
    });
});
