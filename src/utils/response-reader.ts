/**
 * Safe response body reading utilities for scanner services.
 * Used by SBOM, WASM, GraphQL, WebSocket, CSP scanners.
 */

import type { Response } from 'playwright';
import { logger } from './logger.js';

const DEFAULT_MAX_SIZE = 5 * 1024 * 1024; // 5MB

/**
 * Safely read response body as text with size limit.
 */
export async function safeReadResponseBody(response: Response, maxSize = DEFAULT_MAX_SIZE): Promise<string | null> {
    try {
        const contentLength = parseInt(response.headers()['content-length'] || '0', 10);
        if (contentLength > maxSize) {
            logger.debug(`[response-reader] Skipping large response (${contentLength} bytes): ${response.url()}`);
            return null;
        }
        const body = await response.text();
        if (body.length > maxSize) return body.slice(0, maxSize);
        return body;
    } catch {
        return null;
    }
}

/**
 * Safely read response body as Buffer with size limit.
 */
export async function safeReadResponseBuffer(response: Response, maxSize = DEFAULT_MAX_SIZE): Promise<Buffer | null> {
    try {
        const contentLength = parseInt(response.headers()['content-length'] || '0', 10);
        if (contentLength > maxSize) return null;
        return await response.body();
    } catch {
        return null;
    }
}

/**
 * Check if response is a JavaScript file.
 */
export function isJavaScriptResponse(response: Response): boolean {
    const resourceType = response.request().resourceType();
    if (resourceType === 'script') return true;
    const contentType = response.headers()['content-type'] || '';
    return contentType.includes('javascript') || contentType.includes('ecmascript');
}

/**
 * Check if response is a WebAssembly file.
 */
export function isWasmResponse(response: Response): boolean {
    const contentType = response.headers()['content-type'] || '';
    if (contentType.includes('wasm')) return true;
    return response.url().endsWith('.wasm');
}

/**
 * Check if response is a JSON file.
 */
export function isJsonResponse(response: Response): boolean {
    const contentType = response.headers()['content-type'] || '';
    return contentType.includes('json');
}

/**
 * Check if response is a document (HTML page).
 */
export function isDocumentResponse(response: Response): boolean {
    return response.request().resourceType() === 'document';
}
