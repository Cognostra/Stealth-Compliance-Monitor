/**
 * ConsoleMonitor Service
 * 
 * Captures "Red" (Error) logs from the browser console during navigation.
 * Filters out trivial noise to focus on actionable application errors.
 * 
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, ConsoleMessage } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface ConsoleError {
    type: 'error' | 'warning';
    message: string;
    url: string;
    timestamp: number;
}

const IGNORE_PATTERNS = [
    'favicon.ico',
    'sentry',
    'google-analytics',
    'doubleclick',
    '[HMR]', // Hot Module Replacement
    'DeprecationWarning',
    'Third-party cookie',
    'tracking',
    'analytics',
    'mc.yandex.ru'
];

export class ConsoleMonitor implements IScanner {
    readonly name = 'ConsoleMonitor';

    private errors: ConsoleError[] = [];
    private page: Page | null = null;

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Called when page is created - attach console listener
     */
    onPageCreated(page: Page): void {
        if (this.page === page) return;
        this.page = page;

        logger.info('  👂 Console Monitor attached');

        page.on('console', (msg: ConsoleMessage) => {
            if (msg.type() === 'error') {
                this.handleError(msg);
            }
        });
    }

    /**
     * Called during shutdown
     */
    onClose(): void {
        logger.debug(`ConsoleMonitor: Captured ${this.errors.length} console errors`);
    }

    /**
     * Get collected results
     */
    getResults(): ConsoleError[] {
        return this.getErrors();
    }

    /**
     * Clear scanner state
     */
    clear(): void {
        this.errors = [];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Legacy API (for backward compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @deprecated Use ScannerRegistry.register() instead
     * Legacy method for backward compatibility
     */
    public startTracking(page: Page): void {
        this.onPageCreated(page);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Core Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Handle a console error message
     */
    private handleError(msg: ConsoleMessage): void {
        const text = msg.text();
        const url = this.page?.url() || 'unknown';

        // Filter trivial errors
        if (this.isIgnored(text)) {
            return;
        }

        const error: ConsoleError = {
            type: 'error',
            message: text,
            url,
            timestamp: Date.now()
        };

        this.errors.push(error);
        logger.debug(`  🔥 Console Error: ${text.substring(0, 80)}...`);
    }

    /**
     * Check if error should be ignored
     */
    private isIgnored(text: string): boolean {
        return IGNORE_PATTERNS.some(pattern => text.includes(pattern));
    }

    /**
     * Get all captured errors
     */
    public getErrors(): ConsoleError[] {
        return [...this.errors];
    }

    /**
     * Get errors for a specific URL
     */
    public getErrorsForUrl(url: string): ConsoleError[] {
        return this.errors.filter(e => e.url === url);
    }
}
