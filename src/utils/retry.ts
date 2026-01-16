/**
 * Retry Utility
 * 
 * Provides resilient retry logic with exponential backoff and jitter
 * for flaky browser/network operations.
 * 
 * Usage:
 *   await retry(() => page.goto(url), { retries: 3 });
 *   await retry(() => zapService.getAlerts(), { retries: 5, baseDelay: 1000 });
 */

import { Logger } from '../types';

/**
 * Retry configuration options
 */
export interface RetryOptions {
    /** Number of retry attempts (default: 3) */
    retries?: number;
    /** Base delay in ms for exponential backoff (default: 1000) */
    baseDelay?: number;
    /** Maximum delay in ms (default: 30000) */
    maxDelay?: number;
    /** Jitter factor 0-1 to add randomness (default: 0.1) */
    jitter?: number;
    /** Optional logger for debug output */
    logger?: Logger;
    /** Function to determine if error is retryable (default: all errors) */
    shouldRetry?: (error: Error, attempt: number) => boolean;
    /** Callback before each retry */
    onRetry?: (error: Error, attempt: number) => void;
}

/**
 * Default retry options
 */
const DEFAULT_OPTIONS: Required<Omit<RetryOptions, 'logger' | 'onRetry'>> = {
    retries: 3,
    baseDelay: 1000,
    maxDelay: 30000,
    jitter: 0.1,
    shouldRetry: () => true,
};

/**
 * Calculate delay with exponential backoff and jitter
 */
function calculateDelay(
    attempt: number,
    baseDelay: number,
    maxDelay: number,
    jitter: number
): number {
    // Exponential backoff: baseDelay * 2^attempt
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    
    // Cap at maxDelay
    const cappedDelay = Math.min(exponentialDelay, maxDelay);
    
    // Add jitter: random value between -jitter% and +jitter%
    const jitterAmount = cappedDelay * jitter * (Math.random() * 2 - 1);
    
    return Math.floor(cappedDelay + jitterAmount);
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry an async operation with exponential backoff
 * 
 * @param fn - Async function to retry
 * @param options - Retry configuration
 * @returns Result of the function
 * @throws Last error if all retries fail
 * 
 * @example
 * // Basic usage
 * const result = await retry(() => page.goto(url));
 * 
 * @example
 * // With custom options
 * const result = await retry(
 *   () => zapService.getAlerts(),
 *   { retries: 5, baseDelay: 2000, logger }
 * );
 * 
 * @example
 * // With conditional retry
 * const result = await retry(
 *   () => fetchData(),
 *   { 
 *     shouldRetry: (error) => error.message.includes('timeout'),
 *     onRetry: (error, attempt) => console.log(`Retry ${attempt}: ${error.message}`)
 *   }
 * );
 */
export async function retry<T>(
    fn: () => Promise<T>,
    options: RetryOptions = {}
): Promise<T> {
    const config = { ...DEFAULT_OPTIONS, ...options };
    const { retries, baseDelay, maxDelay, jitter, logger, shouldRetry, onRetry } = config;

    let lastError: Error;

    for (let attempt = 1; attempt <= retries + 1; attempt++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error instanceof Error ? error : new Error(String(error));

            // Check if this was the last attempt
            if (attempt > retries) {
                logger?.warn(`Retry exhausted after ${retries} attempts: ${lastError.message}`);
                throw lastError;
            }

            // Check if we should retry this error
            if (!shouldRetry(lastError, attempt)) {
                logger?.debug(`Error not retryable: ${lastError.message}`);
                throw lastError;
            }

            // Calculate delay
            const delay = calculateDelay(attempt, baseDelay, maxDelay, jitter);
            
            logger?.debug(
                `Attempt ${attempt}/${retries} failed: ${lastError.message}. ` +
                `Retrying in ${delay}ms...`
            );

            // Call onRetry callback if provided
            if (onRetry) {
                onRetry(lastError, attempt);
            }

            // Wait before retry
            await sleep(delay);
        }
    }

    // This should never be reached, but TypeScript needs it
    throw lastError!;
}

/**
 * Create a retryable version of an async function
 * 
 * @param fn - Async function to wrap
 * @param options - Retry configuration
 * @returns Wrapped function with retry logic
 * 
 * @example
 * const retryableGoto = withRetry(
 *   (url: string) => page.goto(url),
 *   { retries: 3 }
 * );
 * await retryableGoto('https://example.com');
 */
export function withRetry<TArgs extends unknown[], TResult>(
    fn: (...args: TArgs) => Promise<TResult>,
    options: RetryOptions = {}
): (...args: TArgs) => Promise<TResult> {
    return (...args: TArgs) => retry(() => fn(...args), options);
}

/**
 * Retry with specific error types
 * Only retries if the error matches one of the specified types
 */
export function retryOnErrorTypes<T>(
    fn: () => Promise<T>,
    errorPatterns: (string | RegExp)[],
    options: Omit<RetryOptions, 'shouldRetry'> = {}
): Promise<T> {
    return retry(fn, {
        ...options,
        shouldRetry: (error) => {
            const message = error.message;
            return errorPatterns.some(pattern => 
                typeof pattern === 'string' 
                    ? message.includes(pattern)
                    : pattern.test(message)
            );
        },
    });
}

/**
 * Common retry patterns for Playwright operations
 */
export const PlaywrightRetryPatterns = [
    'timeout',
    'Timeout',
    'net::ERR_',
    'Navigation failed',
    'Target closed',
    'Session closed',
    'Connection refused',
    'Protocol error',
    'Page crashed',
];

/**
 * Common retry patterns for network/API operations
 */
export const NetworkRetryPatterns = [
    'ECONNRESET',
    'ECONNREFUSED',
    'ETIMEDOUT',
    'ENOTFOUND',
    'socket hang up',
    'network timeout',
    'fetch failed',
    '502',
    '503',
    '504',
];

/**
 * Retry specifically for Playwright operations
 */
export function retryPlaywright<T>(
    fn: () => Promise<T>,
    options: Omit<RetryOptions, 'shouldRetry'> = {}
): Promise<T> {
    return retryOnErrorTypes(fn, PlaywrightRetryPatterns, {
        retries: 3,
        baseDelay: 1000,
        ...options,
    });
}

/**
 * Retry specifically for network/API operations
 */
export function retryNetwork<T>(
    fn: () => Promise<T>,
    options: Omit<RetryOptions, 'shouldRetry'> = {}
): Promise<T> {
    return retryOnErrorTypes(fn, NetworkRetryPatterns, {
        retries: 5,
        baseDelay: 2000,
        ...options,
    });
}
