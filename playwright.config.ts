import { defineConfig } from '@playwright/test';

/**
 * Playwright Configuration
 *
 * This config is primarily for the HTML reporter functionality.
 * The actual browser automation is handled by BrowserService.
 */
export default defineConfig({
    // Test directory (if using Playwright Test runner)
    testDir: './src',

    // Reporter configuration
    reporter: [
        // HTML Reporter - generates interactive visual report
        ['html', {
            outputFolder: 'playwright-report',
            open: 'never', // Don't auto-open; we'll prompt user
        }],
        // Also output to console for CI/CD
        ['list'],
    ],

    // Global timeout for tests
    timeout: 120000,

    // Expect timeout
    expect: {
        timeout: 10000,
    },

    // Use the same browser config as BrowserService
    use: {
        // Browser options
        headless: true,
        viewport: { width: 1920, height: 1080 },

        // Artifacts on failure
        screenshot: 'only-on-failure',
        trace: 'retain-on-failure',
        video: 'retain-on-failure',
    },

    // Project configuration
    projects: [
        {
            name: 'chromium',
            use: {
                browserName: 'chromium',
            },
        },
    ],

    // Output folder for traces, screenshots, videos
    outputDir: 'test-results/',

    // Retry failed tests
    retries: 0,

    // Run tests in parallel
    workers: 1, // Single worker for compliance monitoring (sequential)
});
