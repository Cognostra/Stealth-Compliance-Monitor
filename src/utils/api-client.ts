/**
 * Thin fetch wrapper for external API calls.
 * Used by SBOM (OSV API), Container Scanner, K8s, FAIR Risk, Third-Party Risk, and integrations.
 */

import { logger } from './logger.js';

interface FetchOptions {
    timeout?: number;
    headers?: Record<string, string>;
    method?: string;
    body?: string;
}

/**
 * Fetch JSON from a URL with timeout and error handling.
 */
export async function fetchJson<T>(url: string, options: FetchOptions = {}): Promise<T> {
    const { timeout = 10000, headers = {}, method = 'GET', body } = options;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json', ...headers },
            body,
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json() as T;
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Fetch with retry logic for unreliable endpoints.
 */
export async function fetchWithRetry<T>(
    url: string,
    options: FetchOptions & { retries?: number; retryDelay?: number } = {}
): Promise<T> {
    const { retries = 3, retryDelay = 1000, ...fetchOptions } = options;

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            return await fetchJson<T>(url, fetchOptions);
        } catch (error) {
            if (attempt === retries) throw error;
            logger.debug(`[api-client] Retry ${attempt + 1}/${retries} for ${url}: ${(error as Error).message}`);
            await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
        }
    }

    throw new Error(`Failed after ${retries} retries: ${url}`);
}

/**
 * Check if an external service is available by making a HEAD/GET request.
 */
export async function isServiceAvailable(url: string, timeout = 5000): Promise<boolean> {
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timer);
        return response.ok;
    } catch {
        return false;
    }
}
