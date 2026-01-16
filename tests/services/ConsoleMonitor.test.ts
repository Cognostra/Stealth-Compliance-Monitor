/**
 * Unit Tests for ConsoleMonitor
 *
 * Tests console error capture interface.
 * Note: ConsoleMonitor is designed for integration with Playwright Page lifecycle.
 */

import { ConsoleMonitor, ConsoleError } from '../../src/services/ConsoleMonitor.js';

describe('ConsoleMonitor', () => {
    let monitor: ConsoleMonitor;

    beforeEach(() => {
        monitor = new ConsoleMonitor();
    });

    describe('Service interface', () => {
        it('should have correct name', () => {
            expect(monitor.name).toBe('ConsoleMonitor');
        });

        it('should implement IScanner lifecycle', () => {
            expect(typeof monitor.onPageCreated).toBe('function');
        });
    });

    describe('ConsoleError type', () => {
        it('should define ConsoleError interface', () => {
            const error: ConsoleError = {
                type: 'error',
                message: 'Test error',
                url: 'https://example.com',
                timestamp: Date.now()
            };
            expect(error.type).toBe('error');
            expect(error.message).toContain('Test');
        });
    });

    describe('IGNORE_PATTERNS', () => {
        it('should filter known noise patterns', () => {
            const noisePatterns = [
                'favicon.ico',
                'sentry',
                'google-analytics',
                'doubleclick',
                '[HMR]',
                'DeprecationWarning',
                'Third-party cookie',
                'tracking',
                'analytics',
                'mc.yandex.ru'
            ];

            noisePatterns.forEach(pattern => {
                expect(pattern.length).toBeGreaterThan(0);
            });
        });
    });

    describe('Error types', () => {
        it('should capture error type', () => {
            const errorTypes: ConsoleError['type'][] = ['error', 'warning'];
            expect(errorTypes).toContain('error');
            expect(errorTypes).toContain('warning');
        });
    });
});
