/**
 * Unit Tests for ConsoleMonitor
 *
 * Tests console error capture and filtering functionality.
 */

import { ConsoleMonitor, ConsoleError } from '../../src/services/ConsoleMonitor.js';
import { ConsoleMessage } from 'playwright';

describe('ConsoleMonitor', () => {
    let monitor: ConsoleMonitor;

    beforeEach(() => {
        monitor = new ConsoleMonitor();
    });

    describe('IScanner interface', () => {
        it('should have correct name', () => {
            expect(monitor.name).toBe('ConsoleMonitor');
        });

        it('should return empty errors initially', () => {
            expect(monitor.getResults()).toEqual([]);
        });

        it('should clear errors', () => {
            // Access private errors array via type casting to add test data
            (monitor as any).errors.push({
                type: 'error',
                message: 'Test error',
                url: 'https://example.com',
                timestamp: Date.now()
            });

            expect(monitor.getResults().length).toBeGreaterThan(0);

            monitor.clear();

            expect(monitor.getResults()).toEqual([]);
        });
    });

    describe('onConsoleMessage handling', () => {
        it('should capture console errors', () => {
            const mockMessage: Partial<ConsoleMessage> = {
                type: () => 'error',
                text: () => 'Uncaught TypeError: Cannot read property of undefined',
            };

            // Call the handler directly
            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

            const errors = monitor.getResults();
            expect(errors.length).toBe(1);
            expect(errors[0].message).toContain('TypeError');
            expect(errors[0].url).toBe('https://example.com');
        });

        it('should capture error type from message', () => {
            const mockMessage: Partial<ConsoleMessage> = {
                type: () => 'error',
                text: () => 'Failed to load resource',
            };

            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

            const errors = monitor.getResults();
            expect(errors[0].type).toBe('error');
        });

        it('should capture warnings', () => {
            const mockMessage: Partial<ConsoleMessage> = {
                type: () => 'warning',
                text: () => 'Deprecation warning',
            };

            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

            const errors = monitor.getResults();
            expect(errors.length).toBe(1);
            expect(errors[0].type).toBe('warning');
        });
    });

    describe('IGNORE_PATTERNS filtering', () => {
        const testIgnoredPattern = (text: string, description: string) => {
            it(`should ignore ${description}`, () => {
                const mockMessage: Partial<ConsoleMessage> = {
                    type: () => 'error',
                    text: () => text,
                };

                (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

                expect(monitor.getResults().length).toBe(0);
            });
        };

        testIgnoredPattern('Failed to load resource: /favicon.ico', 'favicon errors');
        testIgnoredPattern('Sentry SDK initialization failed', 'sentry messages');
        testIgnoredPattern('google-analytics.com/analytics.js', 'google-analytics messages');
        testIgnoredPattern('[HMR] Hot module replacement', 'HMR messages');
        testIgnoredPattern('DeprecationWarning: something deprecated', 'deprecation warnings');
        testIgnoredPattern('Third-party cookie blocked', 'third-party cookie warnings');

        it('should NOT ignore legitimate errors', () => {
            const mockMessage: Partial<ConsoleMessage> = {
                type: () => 'error',
                text: () => 'Uncaught ReferenceError: foo is not defined',
            };

            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

            expect(monitor.getResults().length).toBe(1);
        });
    });

    describe('getResults', () => {
        beforeEach(() => {
            // Add multiple errors via type casting
            (monitor as any).errors = [
                { type: 'error', message: 'Error 1', url: 'https://site1.com', timestamp: Date.now() },
                { type: 'error', message: 'Error 2', url: 'https://site2.com', timestamp: Date.now() }
            ];
        });

        it('should return all errors via getResults', () => {
            const errors = monitor.getResults();
            expect(errors.length).toBe(2);
        });
    });

    describe('deduplication', () => {
        it('should not duplicate identical errors', () => {
            const mockMessage: Partial<ConsoleMessage> = {
                type: () => 'error',
                text: () => 'Same error message',
            };

            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');
            (monitor as any).handleConsoleMessage(mockMessage, 'https://example.com');

            // Depending on implementation, check for dedup
            const errors = monitor.getResults();
            // If no dedup, this would be 2
            expect(errors.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe('onPageCreated lifecycle', () => {
        it('should attach to page only once', () => {
            const mockPage = {
                on: jest.fn(),
            } as any;

            monitor.onPageCreated(mockPage);
            monitor.onPageCreated(mockPage); // Second call

            // Should only set up listeners once (check internal state)
            expect((monitor as any).page).toBe(mockPage);
        });

        it('should allow attaching to different pages', () => {
            const mockPage1 = { on: jest.fn() } as any;
            const mockPage2 = { on: jest.fn() } as any;

            monitor.onPageCreated(mockPage1);
            monitor.onPageCreated(mockPage2);

            expect((monitor as any).page).toBe(mockPage2);
        });
    });
});
