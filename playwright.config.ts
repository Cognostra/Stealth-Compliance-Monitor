import { defineConfig, devices } from '@playwright/test';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Playwright Configuration for Integration Tests
 *
 * This config handles both:
 * - Integration tests (tests/integration/)
 * - E2E tests with the actual compliance monitor
 */
export default defineConfig({
    // Test directory for integration tests
    testDir: './tests/integration',

    // Test file patterns
    testMatch: ['**/*.spec.ts', '**/*.test.ts'],

    // Fully parallel tests
    fullyParallel: false, // Sequential for compliance monitoring

    // Fail fast on CI
    forbidOnly: !!process.env.CI,

    // Retry on CI only
    retries: process.env.CI ? 2 : 0,

    // Single worker for compliance tests (sequential execution)
    workers: 1,

    // Reporter configuration
    reporter: [
        // HTML Reporter - generates interactive visual report
        ['html', {
            outputFolder: 'playwright-report',
            open: 'never',
        }],
        // Console output for CI/CD
        ['list'],
        // JSON output for programmatic access
        ['json', { outputFile: 'test-results/results.json' }],
    ],

    // Global timeout for tests (2 minutes per test)
    timeout: 120000,

    // Expect timeout
    expect: {
        timeout: 15000,
    },

    // Global setup and teardown
    globalSetup: './tests/integration/global-setup.ts',
    globalTeardown: './tests/integration/global-teardown.ts',

    // Use settings
    use: {
        // Browser options
        headless: true,
        viewport: { width: 1920, height: 1080 },

        // Base URL for tests (defaults to example.com for safety)
        baseURL: process.env.TEST_BASE_URL || 'https://example.com',

        // Artifacts on failure
        screenshot: 'only-on-failure',
        trace: 'retain-on-failure',
        video: 'retain-on-failure',

        // Action timeout
        actionTimeout: 30000,

        // Navigation timeout
        navigationTimeout: 60000,
    },

    // Project configuration
    projects: [
        // Unit-style integration tests (no browser needed)
        {
            name: 'unit-integration',
            testMatch: ['**/unit/**/*.spec.ts'],
            use: {},
        },
        // Browser integration tests
        {
            name: 'chromium',
            testMatch: ['**/browser/**/*.spec.ts', '**/e2e/**/*.spec.ts'],
            use: {
                ...devices['Desktop Chrome'],
            },
        },
        // Full E2E with ZAP (requires docker-compose)
        {
            name: 'e2e-with-zap',
            testMatch: ['**/e2e-zap/**/*.spec.ts'],
            use: {
                ...devices['Desktop Chrome'],
                // ZAP proxy configuration
                proxy: {
                    server: process.env.ZAP_PROXY_URL || 'http://localhost:8080',
                },
            },
        },
    ],

    // Output folder for traces, screenshots, videos
    outputDir: 'test-results/',

    // Web server for local testing (optional)
    // webServer: {
    //     command: 'npm run start:test-server',
    //     port: 3000,
    //     reuseExistingServer: !process.env.CI,
    // },
});
