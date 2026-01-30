/**
 * Shared page.evaluate() helpers for scanner services.
 * Used by CSP, Fingerprinting, WebRTC, PWA, Extension, Mobile, Shadow DOM scanners.
 */

import type { Page } from 'playwright';
import { logger } from './logger.js';

/**
 * Safely evaluate a function in the page context with error handling.
 */
export async function safeEvaluate<T>(page: Page, fn: (() => T) | string): Promise<T | null> {
    try {
        return await page.evaluate(fn);
    } catch (error) {
        logger.debug(`[page-helpers] evaluate failed: ${(error as Error).message}`);
        return null;
    }
}

/**
 * Extract all script elements with their sources and inline content.
 */
export async function getPageScripts(page: Page): Promise<{ src: string; content: string }[]> {
    return safeEvaluate(page, () => {
        const scripts: { src: string; content: string }[] = [];
        document.querySelectorAll('script').forEach(s => {
            scripts.push({
                src: s.src || '',
                content: s.src ? '' : (s.textContent || '').slice(0, 10000),
            });
        });
        return scripts;
    }) ?? [];
}

/**
 * Read localStorage and sessionStorage contents.
 */
export async function getStorageContents(page: Page): Promise<{
    localStorage: Record<string, string>;
    sessionStorage: Record<string, string>;
}> {
    return safeEvaluate(page, () => {
        const readStorage = (storage: Storage): Record<string, string> => {
            const data: Record<string, string> = {};
            for (let i = 0; i < Math.min(storage.length, 100); i++) {
                const key = storage.key(i);
                if (key) data[key] = (storage.getItem(key) || '').slice(0, 1000);
            }
            return data;
        };
        return {
            localStorage: readStorage(localStorage),
            sessionStorage: readStorage(sessionStorage),
        };
    }) ?? { localStorage: {}, sessionStorage: {} };
}

/**
 * Get page metadata (title, url, meta tags).
 */
export async function getPageMetadata(page: Page): Promise<{
    title: string;
    url: string;
    metaTags: { name: string; content: string }[];
}> {
    return safeEvaluate(page, () => {
        const metaTags: { name: string; content: string }[] = [];
        document.querySelectorAll('meta').forEach(m => {
            const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || '';
            const content = m.getAttribute('content') || '';
            if (name) metaTags.push({ name, content });
        });
        return { title: document.title, url: location.href, metaTags };
    }) ?? { title: '', url: page.url(), metaTags: [] };
}
