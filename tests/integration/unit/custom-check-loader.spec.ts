/**
 * Unit Tests: Custom Check Loader
 * 
 * Tests the dynamic loading and execution of custom compliance checks.
 */

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';
import { CustomCheckLoader, CustomCheckContext, CustomCheckViolation } from '../../../src/core/CustomCheckLoader.js';
import { Page } from 'playwright';

// Mock logger
const mockLogger = {
    info: () => { },
    warn: () => { },
    error: () => { },
    debug: () => { },
};

// Test directory for temporary checks
const TEST_CHECKS_DIR = path.resolve(__dirname, 'temp_checks');

test.describe('Custom Check Loader', () => {

    test.beforeAll(() => {
        if (!fs.existsSync(TEST_CHECKS_DIR)) {
            fs.mkdirSync(TEST_CHECKS_DIR);
        }
    });

    test.afterAll(() => {
        if (fs.existsSync(TEST_CHECKS_DIR)) {
            fs.rmSync(TEST_CHECKS_DIR, { recursive: true, force: true });
        }
    });

    test.afterEach(() => {
        // Clean up files in temp dir
        const files = fs.readdirSync(TEST_CHECKS_DIR);
        for (const file of files) {
            fs.unlinkSync(path.join(TEST_CHECKS_DIR, file));
        }
    });

    test('should return 0 checks if directory does not exist', async () => {
        const loader = new CustomCheckLoader(mockLogger, './non-existent-dir');
        const count = await loader.loadChecks();
        expect(count).toBe(0);
    });

    test('should load valid check files', async () => {
        const checkContent = `
            module.exports = {
                check: async (page, context) => {
                    return [];
                }
            };
        `;
        fs.writeFileSync(path.join(TEST_CHECKS_DIR, 'valid-check.js'), checkContent);

        const loader = new CustomCheckLoader(mockLogger, TEST_CHECKS_DIR);
        const count = await loader.loadChecks();
        expect(count).toBe(1);
        expect(loader.getLoadedCheckNames()).toContain('valid-check');
    });

    test('should ignore non-check files', async () => {
        fs.writeFileSync(path.join(TEST_CHECKS_DIR, 'README.md'), '# Readme');
        fs.writeFileSync(path.join(TEST_CHECKS_DIR, 'types.d.ts'), 'export type Foo = string;');

        const loader = new CustomCheckLoader(mockLogger, TEST_CHECKS_DIR);
        const count = await loader.loadChecks();
        expect(count).toBe(0);
    });

    test('should execute check and return results', async ({ page }) => {
        const checkContent = `
            module.exports = {
                check: async (page, context) => {
                    return [{
                        id: 'test-violation',
                        title: 'Test Violation',
                        severity: 'high',
                        description: 'This is a test'
                    }];
                }
            };
        `;
        fs.writeFileSync(path.join(TEST_CHECKS_DIR, 'test-check.js'), checkContent);

        const loader = new CustomCheckLoader(mockLogger, TEST_CHECKS_DIR);
        await loader.loadChecks();

        const context: CustomCheckContext = {
            targetUrl: 'http://example.com',
            currentUrl: 'http://example.com',
            visitedUrls: [],
            logger: mockLogger,
            profile: 'test'
        };

        const results = await loader.runChecks(page, context);

        expect(results).toHaveLength(1);
        expect(results[0].name).toBe('test-check');
        expect(results[0].passed).toBe(false);
        expect(results[0].violations).toHaveLength(1);
        expect(results[0].violations[0].id).toBe('test-violation');
    });

    test('should handle check timeout', async ({ page }) => {
        const checkContent = `
            module.exports = {
                check: async (page, context) => {
                    await new Promise(resolve => setTimeout(resolve, 200));
                    return [];
                }
            };
        `;
        fs.writeFileSync(path.join(TEST_CHECKS_DIR, 'slow-check.js'), checkContent);

        // Set short timeout
        const loader = new CustomCheckLoader(mockLogger, TEST_CHECKS_DIR, 100);
        await loader.loadChecks();

        const context: CustomCheckContext = {
            targetUrl: 'http://example.com',
            currentUrl: 'http://example.com',
            visitedUrls: [],
            logger: mockLogger,
            profile: 'test'
        };

        const results = await loader.runChecks(page, context);

        expect(results).toHaveLength(1);
        expect(results[0].passed).toBe(false);
        expect(results[0].error).toContain('timeout');
    });
});
