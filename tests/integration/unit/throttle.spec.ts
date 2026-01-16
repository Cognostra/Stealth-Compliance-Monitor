/**
 * Unit Tests: Throttle Utility
 * 
 * Tests rate limiting, human delay, and throttled function behavior.
 */

import { test, expect } from '@playwright/test';

import {
    randomDelay,
    sleep,
    humanDelay,
    createThrottledFunction,
    RateLimiter
} from '../../../src/utils/throttle.js';

test.describe('Throttle Utility', () => {
    test.describe('randomDelay()', () => {
        test('should return value within range', () => {
            const min = 100;
            const max = 500;

            for (let i = 0; i < 20; i++) {
                const delay = randomDelay(min, max);
                expect(delay).toBeGreaterThanOrEqual(min);
                expect(delay).toBeLessThanOrEqual(max);
            }
        });

        test('should return integer values', () => {
            const delay = randomDelay(100, 500);
            expect(Number.isInteger(delay)).toBe(true);
        });

        test('should handle equal min and max', () => {
            const delay = randomDelay(100, 100);
            expect(delay).toBe(100);
        });
    });

    test.describe('sleep()', () => {
        test('should resolve after specified time', async () => {
            const start = Date.now();
            await sleep(50);
            const elapsed = Date.now() - start;

            // Allow 20ms tolerance
            expect(elapsed).toBeGreaterThanOrEqual(45);
            expect(elapsed).toBeLessThan(100);
        });

        test('should resolve immediately for 0ms', async () => {
            const start = Date.now();
            await sleep(0);
            const elapsed = Date.now() - start;

            expect(elapsed).toBeLessThan(20);
        });
    });

    test.describe('humanDelay()', () => {
        test('should wait within specified range', async () => {
            const start = Date.now();
            await humanDelay(50, 100);
            const elapsed = Date.now() - start;

            expect(elapsed).toBeGreaterThanOrEqual(45);
            expect(elapsed).toBeLessThanOrEqual(150);
        });

        test('should log when logger provided', async () => {
            const logs: string[] = [];
            const mockLogger = {
                debug: (msg: string) => logs.push(msg),
                info: () => { },
                warn: () => { },
                error: () => { },
            };

            await humanDelay(10, 20, mockLogger);

            expect(logs.length).toBe(1);
            expect(logs[0]).toContain('Throttle: waiting');
        });
    });

    test.describe('createThrottledFunction()', () => {
        test('should throttle rapid calls', async () => {
            let callCount = 0;
            const fn = async () => {
                callCount++;
                return callCount;
            };

            const throttled = createThrottledFunction(fn, 50, 100);

            const start = Date.now();
            await throttled();
            await throttled();
            const elapsed = Date.now() - start;

            expect(callCount).toBe(2);
            // Second call should wait at least 50ms
            expect(elapsed).toBeGreaterThanOrEqual(45);
        });

        test('should preserve function arguments', async () => {
            const fn = async (a: number, b: number) => a + b;
            const throttled = createThrottledFunction(fn, 10, 20);

            const result = await throttled(2, 3);
            expect(result).toBe(5);
        });
    });

    test.describe('RateLimiter', () => {
        test('should wait before first action', async () => {
            const limiter = new RateLimiter(50, 100);

            const start = Date.now();
            await limiter.waitBeforeAction();
            const elapsed = Date.now() - start;

            // First action should not wait (no previous action)
            expect(elapsed).toBeLessThan(20);
        });

        test('should enforce delay between actions', async () => {
            const limiter = new RateLimiter(50, 100);

            await limiter.waitBeforeAction();
            const start = Date.now();
            await limiter.waitBeforeAction();
            const elapsed = Date.now() - start;

            expect(elapsed).toBeGreaterThanOrEqual(45);
        });

        test('should execute actions with rate limiting', async () => {
            const limiter = new RateLimiter(30, 50);
            const results: number[] = [];

            const start = Date.now();
            await limiter.execute(async () => { results.push(1); });
            await limiter.execute(async () => { results.push(2); });
            const elapsed = Date.now() - start;

            expect(results).toEqual([1, 2]);
            expect(elapsed).toBeGreaterThanOrEqual(25);
        });

        test('should log when logger provided', async () => {
            const logs: string[] = [];
            const mockLogger = {
                debug: (msg: string) => logs.push(msg),
                info: () => { },
                warn: () => { },
                error: () => { },
            };

            const limiter = new RateLimiter(50, 100, mockLogger);

            await limiter.waitBeforeAction();
            await limiter.waitBeforeAction();

            // Should have logged the wait
            expect(logs.some(l => l.includes('Rate limiter'))).toBe(true);
        });
    });
});
