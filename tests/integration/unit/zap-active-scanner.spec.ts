/**
 * Unit Tests: ZAP Active Scanner
 * 
 * Tests the active scanning service functionality.
 * Note: These are unit tests that mock the ZAP API - no actual ZAP required.
 */

import { test, expect } from '@playwright/test';

// Import the service for testing
import { ZapActiveScanner } from '../../../src/services/ZapActiveScanner.js';
import { EnvConfig } from '../../../src/config/env.js';

// Mock logger
const mockLogger = {
    info: (): void => { },
    warn: (): void => { },
    error: (): void => { },
    debug: (): void => { },
};

// Mock config
const mockConfig: Partial<EnvConfig> = {
    LIVE_URL: 'https://example.com',
    ZAP_PROXY_URL: 'http://localhost:8080',
    ZAP_API_KEY: 'test-api-key',
};

test.describe('ZAP Active Scanner', () => {
    test.describe('Constructor and Configuration', () => {
        test('should create instance with valid config', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);
            expect(scanner).toBeDefined();
        });

        test('should handle config without API key', () => {
            const configWithoutKey = { ...mockConfig, ZAP_API_KEY: undefined };
            const scanner = new ZapActiveScanner(configWithoutKey as EnvConfig, mockLogger);
            expect(scanner).toBeDefined();
        });
    });

    test.describe('Warning Display', () => {
        test('should display warning without throwing', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            // Capture console output
            const originalLog = console.log;
            const logs: string[] = [];
            console.log = (msg: string) => logs.push(msg);

            scanner.displayActiveWarning();

            console.log = originalLog;

            // Check that warning was displayed
            expect(logs.some(l => l.includes('WARNING'))).toBe(true);
            expect(logs.some(l => l.includes('ACTIVE SCANNING'))).toBe(true);
        });
    });

    test.describe('URL Building', () => {
        test('should build URL with API key', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            // Access private method via prototype
            const buildUrl = (scanner as unknown as {
                buildUrl: (endpoint: string, params?: Record<string, string>) => string
            }).buildUrl.bind(scanner);

            const url = buildUrl('/JSON/core/view/version/');

            expect(url).toContain('http://localhost:8080');
            expect(url).toContain('apikey=test-api-key');
        });

        test('should include additional params', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            const buildUrl = (scanner as unknown as {
                buildUrl: (endpoint: string, params?: Record<string, string>) => string
            }).buildUrl.bind(scanner);

            const url = buildUrl('/JSON/spider/action/scan/', { url: 'https://example.com' });

            expect(url).toContain('url=https%3A%2F%2Fexample.com');
        });
    });

    test.describe('Alert Risk Mapping', () => {
        test('should map High risk correctly', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            const mapRisk = (scanner as unknown as {
                mapRisk: (risk: string) => string
            }).mapRisk.bind(scanner);

            expect(mapRisk('high')).toBe('High');
            expect(mapRisk('HIGH')).toBe('High');
        });

        test('should map Medium risk correctly', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            const mapRisk = (scanner as unknown as {
                mapRisk: (risk: string) => string
            }).mapRisk.bind(scanner);

            expect(mapRisk('medium')).toBe('Medium');
            expect(mapRisk('MEDIUM')).toBe('Medium');
        });

        test('should default to Informational for unknown risks', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            const mapRisk = (scanner as unknown as {
                mapRisk: (risk: string) => string
            }).mapRisk.bind(scanner);

            expect(mapRisk('unknown')).toBe('Informational');
            expect(mapRisk('')).toBe('Informational');
        });
    });

    test.describe('Alert Mapping', () => {
        test('should map ZAP alert to SecurityAlert format', () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            const mapAlert = (scanner as unknown as {
                mapAlert: (alert: Record<string, string>) => Record<string, string>
            }).mapAlert.bind(scanner);

            const zapAlert = {
                id: '1',
                name: 'Cross Site Scripting',
                risk: 'High',
                description: 'XSS vulnerability detected',
                solution: 'Encode user input',
                url: 'https://example.com/page',
                confidence: 'Medium',
            };

            const result = mapAlert(zapAlert);

            expect(result.name).toBe('Cross Site Scripting');
            expect(result.risk).toBe('High');
            expect(result.description).toBe('XSS vulnerability detected');
            expect(result.url).toBe('https://example.com/page');
        });
    });

    test.describe('Cleanup', () => {
        test('should cleanup without throwing when not initialized', async () => {
            const scanner = new ZapActiveScanner(mockConfig as EnvConfig, mockLogger);

            // Should not throw even without ZAP running
            await expect(scanner.cleanup()).resolves.not.toThrow();
        });
    });
});
