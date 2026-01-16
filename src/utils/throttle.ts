/**
 * Throttling Utilities
 * Human-like delays to prevent WAF blocking
 */

import { Logger } from '../types/index.js';

/**
 * Generate a random delay between min and max milliseconds
 */
export function randomDelay(minMs: number, maxMs: number): number {
    return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Human-like delay with logging
 * Waits between 2-5 seconds (configurable) to mimic human behavior
 */
export async function humanDelay(
    minMs: number = 2000,
    maxMs: number = 5000,
    logger?: Logger
): Promise<void> {
    const delay = randomDelay(minMs, maxMs);

    if (logger) {
        logger.debug(`Throttle: waiting ${delay}ms`);
    }

    await sleep(delay);
}

/**
 * Create a throttled function that ensures minimum delay between calls
 */
export function createThrottledFunction<T extends (...args: unknown[]) => Promise<unknown>>(
    fn: T,
    minDelayMs: number = 2000,
    maxDelayMs: number = 5000
): T {
    let lastCallTime = 0;

    return (async (...args: Parameters<T>): Promise<Awaited<ReturnType<T>>> => {
        const now = Date.now();
        const timeSinceLastCall = now - lastCallTime;
        const requiredDelay = randomDelay(minDelayMs, maxDelayMs);

        if (timeSinceLastCall < requiredDelay) {
            await sleep(requiredDelay - timeSinceLastCall);
        }

        lastCallTime = Date.now();
        return fn(...args) as Awaited<ReturnType<T>>;
    }) as T;
}

/**
 * Rate limiter class for more complex scenarios
 */
export class RateLimiter {
    private readonly minDelayMs: number;
    private readonly maxDelayMs: number;
    private readonly logger?: Logger;
    private lastActionTime: number = 0;

    constructor(minDelayMs: number = 2000, maxDelayMs: number = 5000, logger?: Logger) {
        this.minDelayMs = minDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.logger = logger;
    }

    /**
     * Wait before next action
     */
    async waitBeforeAction(): Promise<void> {
        const now = Date.now();
        const timeSinceLastAction = now - this.lastActionTime;
        const requiredDelay = randomDelay(this.minDelayMs, this.maxDelayMs);

        if (timeSinceLastAction < requiredDelay) {
            const waitTime = requiredDelay - timeSinceLastAction;
            this.logger?.debug(`Rate limiter: waiting ${waitTime}ms before next action`);
            await sleep(waitTime);
        }

        this.lastActionTime = Date.now();
    }

    /**
     * Execute action with rate limiting
     */
    async execute<T>(action: () => Promise<T>): Promise<T> {
        await this.waitBeforeAction();
        return action();
    }
}
