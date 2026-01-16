/**
 * Unit Tests: Retry Utility
 * 
 * Tests exponential backoff, jitter, and retry behavior.
 */

import { test, expect } from '@playwright/test';

// Import from source
import {
    retry,
    withRetry,
    retryOnErrorTypes,
    PlaywrightRetryPatterns,
    NetworkRetryPatterns
} from '../../../src/utils/retry';

test.describe('Retry Utility', () => {
    test.describe('retry()', () => {
        test('should succeed on first attempt', async () => {
            let attempts = 0;
            const result = await retry(async () => {
                attempts++;
                return 'success';
            });

            expect(result).toBe('success');
            expect(attempts).toBe(1);
        });

        test('should retry on failure and eventually succeed', async () => {
            let attempts = 0;
            const result = await retry(async () => {
                attempts++;
                if (attempts < 3) {
                    throw new Error('Temporary failure');
                }
                return 'success after retries';
            }, { retries: 3, baseDelay: 10 }); // Fast retries for testing

            expect(result).toBe('success after retries');
            expect(attempts).toBe(3);
        });

        test('should throw after max retries exceeded', async () => {
            let attempts = 0;

            await expect(retry(async () => {
                attempts++;
                throw new Error('Persistent failure');
            }, { retries: 2, baseDelay: 10 })).rejects.toThrow('Persistent failure');

            expect(attempts).toBe(3); // 1 initial + 2 retries
        });

        test('should respect shouldRetry option', async () => {
            let attempts = 0;

            await expect(retry(async () => {
                attempts++;
                throw new Error('Non-retryable error');
            }, {
                retries: 5,
                baseDelay: 10,
                shouldRetry: () => false // Never retry
            })).rejects.toThrow('Non-retryable error');

            expect(attempts).toBe(1); // Should not retry
        });

        test('should call onRetry callback', async () => {
            const retryLog: number[] = [];

            await expect(retry(async () => {
                throw new Error('Always fails');
            }, {
                retries: 2,
                baseDelay: 10,
                onRetry: (_, attempt) => retryLog.push(attempt)
            })).rejects.toThrow();

            expect(retryLog).toEqual([1, 2]);
        });
    });

    test.describe('withRetry()', () => {
        test('should wrap function with retry logic', async () => {
            let attempts = 0;
            const unstableFunction = async (value: number) => {
                attempts++;
                if (attempts < 2) throw new Error('Flaky');
                return value * 2;
            };

            const stableFunction = withRetry(unstableFunction, { retries: 3, baseDelay: 10 });
            const result = await stableFunction(21);

            expect(result).toBe(42);
            expect(attempts).toBe(2);
        });
    });

    test.describe('retryOnErrorTypes()', () => {
        test('should retry only for matching error patterns', async () => {
            let attempts = 0;

            const result = await retryOnErrorTypes(async () => {
                attempts++;
                if (attempts < 2) throw new Error('timeout error');
                return 'recovered';
            }, ['timeout'], { retries: 3, baseDelay: 10 });

            expect(result).toBe('recovered');
            expect(attempts).toBe(2);
        });

        test('should not retry for non-matching errors', async () => {
            let attempts = 0;

            await expect(retryOnErrorTypes(async () => {
                attempts++;
                throw new Error('unrelated error');
            }, ['timeout', 'network'], { retries: 3, baseDelay: 10 })).rejects.toThrow('unrelated error');

            expect(attempts).toBe(1);
        });

        test('should support regex patterns', async () => {
            let attempts = 0;

            const result = await retryOnErrorTypes(async () => {
                attempts++;
                if (attempts < 2) throw new Error('net::ERR_CONNECTION_REFUSED');
                return 'recovered';
            }, [/net::ERR_/], { retries: 3, baseDelay: 10 });

            expect(result).toBe('recovered');
        });
    });

    test.describe('Retry Patterns', () => {
        test('PlaywrightRetryPatterns should contain expected patterns', () => {
            expect(PlaywrightRetryPatterns).toContain('timeout');
            expect(PlaywrightRetryPatterns).toContain('Navigation failed');
            expect(PlaywrightRetryPatterns).toContain('net::ERR_');
        });

        test('NetworkRetryPatterns should contain expected patterns', () => {
            expect(NetworkRetryPatterns).toContain('ECONNRESET');
            expect(NetworkRetryPatterns).toContain('ETIMEDOUT');
            expect(NetworkRetryPatterns).toContain('fetch failed');
        });
    });
});
