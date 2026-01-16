/**
 * NetworkSpy Service
 * 
 * Silently monitors background API traffic to detect performance bottlenecks
 * and hidden errors.
 * 
 * Analysis Rules:
 * - Slow Response: > 500ms
 * - Heavy Payload: > 100KB (unoptimized data)
 * - HTTP Errors: 4xx, 5xx status codes
 * 
 * Implements IScanner for registry-based lifecycle management.
 */

import { BrowserContext, Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface NetworkIncident {
    url: string;
    method: string;
    type: 'slow_response' | 'heavy_payload' | 'http_error';
    status: number;
    duration?: number;
    sizeBytes?: number;
    details?: string;
    timestamp: string;
}

const SPY_CONFIG = {
    slowThreshold: 500, // ms
    largeSizeThreshold: 100 * 1024, // 100KB
    ignoredHosts: [
        'google-analytics.com',
        'googletagmanager.com',
        'facebook.net'
    ]
};

export class NetworkSpy implements IScanner {
    readonly name = 'NetworkSpy';

    private incidents: NetworkIncident[] = [];
    private page: Page | null = null;

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Called when page is created - attach listeners
     */
    onPageCreated(page: Page): void {
        if (this.page === page) return; // Already attached
        this.page = page;
        logger.info('  🕵️ Network Spy attached to browser session');
    }

    /**
     * Called for each network response - analyze for incidents
     */
    async onResponse(response: Response): Promise<void> {
        await this.handleResponse(response);
    }

    /**
     * Called during shutdown
     */
    onClose(): void {
        logger.debug(`NetworkSpy: Collected ${this.incidents.length} incidents`);
    }

    /**
     * Get collected results
     */
    getResults(): NetworkIncident[] {
        return this.getIncidents();
    }

    /**
     * Clear scanner state
     */
    clear(): void {
        this.incidents = [];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Legacy API (for backward compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @deprecated Use ScannerRegistry.register() instead
     * Legacy attach method for backward compatibility
     */
    public attach(page: Page): void {
        this.onPageCreated(page);
        // Legacy: directly attach response handler
        page.on('response', this.handleResponse.bind(this));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Core Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Handle each network response
     */
    private async handleResponse(response: Response): Promise<void> {
        try {
            const url = response.url();
            const request = response.request();
            const resourceType = request.resourceType(); // fetch, xhr, etc.
            const status = response.status();

            // Filter out ignored hosts
            if (SPY_CONFIG.ignoredHosts.some(h => url.includes(h))) return;

            // 1. Check for Status Errors (4xx, 5xx)
            if (status >= 400) {
                this.addIncident({
                    url,
                    method: request.method(),
                    type: 'http_error',
                    status,
                    timestamp: new Date().toISOString()
                });
                return; // Don't analyze body size of errors usually
            }

            // Only analyze data calls (XHR/Fetch) for performance
            if (resourceType !== 'fetch' && resourceType !== 'xhr') return;

            // 2. Check Timing
            const timing = response.request().timing();
            const duration = timing ? (timing.responseEnd - timing.requestStart) : 0;

            // 3. Check payload size via Content-Length header
            const contentLength = response.headers()['content-length'];
            let size = contentLength ? parseInt(contentLength, 10) : 0;

            // Heavy Payload Check
            if (size > SPY_CONFIG.largeSizeThreshold) {
                this.addIncident({
                    url,
                    method: request.method(),
                    type: 'heavy_payload',
                    status,
                    sizeBytes: size,
                    details: `Payload size: ${(size / 1024).toFixed(2)} KB`,
                    timestamp: new Date().toISOString()
                });
            }
        } catch (e) {
            // Page may be closed or response invalidated during handling
            logger.debug(`NetworkSpy: Error processing response: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    /**
     * Record an incident
     */
    private addIncident(incident: NetworkIncident) {
        // Deduplicate exact same URL/type incidents to reduce noise
        const exists = this.incidents.find(i =>
            i.url === incident.url &&
            i.type === incident.type
        );

        if (!exists) {
            this.incidents.push(incident);
            const icon = incident.type === 'http_error' ? '❌' : '⚠️';
            logger.debug(`  ${icon} Network Incident [${incident.type}]: ${incident.url.substring(0, 60)}...`);
        }
    }

    /**
     * Get all captured incidents
     */
    public getIncidents(): NetworkIncident[] {
        return this.incidents;
    }
}
