/**
 * ScannerRegistry - Observer Pattern Implementation
 * 
 * Decouples BrowserService from specific scanner implementations.
 * Scanners register themselves and receive lifecycle hooks during browser operations.
 * 
 * This enables:
 * - Plugin-style scanner architecture
 * - Easy addition/removal of scanners without modifying BrowserService
 * - Cleaner separation of concerns
 * - Better testability
 */

import { BrowserContext, Page, Request, Response } from 'playwright';
import pLimit from 'p-limit';
import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER INTERFACE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * IScanner Interface
 * 
 * All scanners must implement this interface to receive browser lifecycle hooks.
 * Methods are optional - implement only what your scanner needs.
 */
export interface IScanner {
    /** Unique identifier for the scanner */
    readonly name: string;

    /**
     * Called when a new browser context is created.
     * Use for context-level setup (e.g., route interception).
     */
    onContextCreated?(context: BrowserContext): void | Promise<void>;

    /**
     * Called when a new page is created within the context.
     * Primary hook for attaching page-level listeners.
     */
    onPageCreated?(page: Page): void | Promise<void>;

    /**
     * Called for each network request made by the page.
     * Use for request inspection/modification.
     */
    onRequest?(request: Request): void | Promise<void>;

    /**
     * Called for each network response received.
     * Use for response analysis (headers, body, timing).
     */
    onResponse?(response: Response): void | Promise<void>;

    /**
     * Called when the browser service is closing.
     * Use for cleanup and final data collection.
     */
    onClose?(): void | Promise<void>;

    /**
     * Get results collected by this scanner.
     * Returns scanner-specific data structure.
     */
    getResults?(): unknown;

    /**
     * Clear/reset scanner state.
     */
    clear?(): void;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER RESULT TYPES (for typed access)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Type map for scanner results.
 * Add entries here as scanners are implemented.
 */
export interface ScannerResultMap {
    'NetworkSpy': import('../services/NetworkSpy.js').NetworkIncident[];
    'SecretScanner': import('../services/SecretScanner.js').LeakedSecret[];
    'ConsoleMonitor': import('../services/ConsoleMonitor.js').ConsoleError[];
    'SupabaseSecurityScanner': import('../services/SupabaseSecurityScanner.js').SupabaseSecurityIssue[];
    'FrontendVulnerabilityScanner': import('../services/FrontendVulnerabilityScanner.js').VulnerableLibrary[];
    'FintechScanner': import('../services/FintechScanner.js').FintechFinding[];
    'FlutterSemanticsScanner': import('../services/FlutterSemanticsScanner.js').FlutterSemanticsIssue[];
    // v3.2 Scanner Result Types - Phase 1: Core Security
    'SbomScanner': import('../services/SbomScanner.js').DetectedPackage[];
    'GraphQLDeepScanner': import('../services/GraphQLDeepScanner.js').GraphQLFinding[];
    'WebSocketAuditor': import('../services/WebSocketAuditor.js').WebSocketFinding[];
    'CspViolationCollector': import('../services/CspViolationCollector.js').CspFinding[];
    // v3.2 Scanner Result Types - Phase 2: AI-Powered
    'FingerprintDetector': import('../services/FingerprintDetector.js').FingerprintFinding[];
    // v3.2 Scanner Result Types - Phase 3: Web Platform
    'WebRTCAnalyzer': import('../services/WebRTCAnalyzer.js').WebRTCFinding[];
    'PwaSecurityScanner': import('../services/PwaSecurityScanner.js').PwaFinding[];
    'ExtensionAuditScanner': import('../services/ExtensionAuditScanner.js').ExtensionFinding[];
    'MobileSecurityScanner': import('../services/MobileSecurityScanner.js').MobileFinding[];
    'ShadowDomScanner': import('../services/ShadowDomScanner.js').ShadowDomFinding[];
    // v3.2 Scanner Result Types - Phase 4: Infrastructure
    'WasmSecurityScanner': import('../services/WasmSecurityScanner.js').WasmFinding[];
    [key: string]: unknown;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER REGISTRY CLASS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * ScannerRegistry Class
 * 
 * Central registry for all scanner plugins.
 * Manages scanner lifecycle and distributes browser events.
 */
export class ScannerRegistry {
    private static readonly REQUEST_CONCURRENCY = 8;
    private static readonly RESPONSE_CONCURRENCY = 4;
    private scanners: Map<string, IScanner> = new Map();
    private context: BrowserContext | null = null;
    private page: Page | null = null;
    private requestLimiter = pLimit(ScannerRegistry.REQUEST_CONCURRENCY);
    private responseLimiter = pLimit(ScannerRegistry.RESPONSE_CONCURRENCY);

    /**
     * Register a scanner with the registry.
     * @param scanner - Scanner instance implementing IScanner
     */
    register(scanner: IScanner): void {
        if (this.scanners.has(scanner.name)) {
            logger.warn(`Scanner "${scanner.name}" is already registered. Skipping.`);
            return;
        }

        this.scanners.set(scanner.name, scanner);
        logger.debug(`📦 Scanner registered: ${scanner.name}`);
    }

    /**
     * Unregister a scanner by name.
     * @param name - Scanner name to remove
     */
    unregister(name: string): boolean {
        const removed = this.scanners.delete(name);
        if (removed) {
            logger.debug(`📦 Scanner unregistered: ${name}`);
        }
        return removed;
    }

    /**
     * Get a registered scanner by name.
     * @param name - Scanner name
     */
    getScanner<T extends IScanner>(name: string): T | undefined {
        return this.scanners.get(name) as T | undefined;
    }

    /**
     * Get results from a specific scanner with type safety.
     * @param name - Scanner name
     */
    getResults<K extends keyof ScannerResultMap>(name: K): ScannerResultMap[K] | undefined {
        const scanner = this.scanners.get(name as string);
        if (scanner?.getResults) {
            return scanner.getResults() as ScannerResultMap[K];
        }
        return undefined;
    }

    /**
     * Get all registered scanner names.
     */
    getScannerNames(): string[] {
        return Array.from(this.scanners.keys());
    }

    /**
     * Get count of registered scanners.
     */
    get count(): number {
        return this.scanners.size;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LIFECYCLE HOOK DISPATCHERS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Dispatch context creation event to all scanners.
     * Called by BrowserService after creating the browser context.
     */
    async dispatchContextCreated(context: BrowserContext): Promise<void> {
        this.context = context;

        const promises: Promise<void>[] = [];

        for (const [name, scanner] of this.scanners) {
            if (scanner.onContextCreated) {
                try {
                    const result = scanner.onContextCreated(context);
                    if (result instanceof Promise) {
                        promises.push(result.catch(err => {
                            logger.error(`Scanner "${name}" error in onContextCreated: ${err}`);
                        }));
                    }
                } catch (error) {
                    logger.error(`Scanner "${name}" error in onContextCreated: ${error}`);
                }
            }
        }

        await Promise.all(promises);
        logger.debug(`Dispatched onContextCreated to ${this.count} scanners`);
    }

    /**
     * Dispatch page creation event to all scanners.
     * Called by BrowserService after creating a new page.
     */
    async dispatchPageCreated(page: Page): Promise<void> {
        this.page = page;

        // Attach global request/response handlers that dispatch to scanners
        this.attachPageEventHandlers(page);

        const promises: Promise<void>[] = [];

        for (const [name, scanner] of this.scanners) {
            if (scanner.onPageCreated) {
                try {
                    const result = scanner.onPageCreated(page);
                    if (result instanceof Promise) {
                        promises.push(result.catch(err => {
                            logger.error(`Scanner "${name}" error in onPageCreated: ${err}`);
                        }));
                    }
                } catch (error) {
                    logger.error(`Scanner "${name}" error in onPageCreated: ${error}`);
                }
            }
        }

        await Promise.all(promises);
        logger.debug(`  🔌 ${this.count} scanners attached to page`);
    }

    /**
     * Attach page event handlers that dispatch to individual scanners.
     */
    private attachPageEventHandlers(page: Page): void {
        // Request handler
        page.on('request', (request: Request) => {
            this.dispatchRequest(request);
        });

        // Response handler
        page.on('response', (response: Response) => {
            this.dispatchResponse(response);
        });
    }

    /**
     * Dispatch request event to all scanners.
     */
    private dispatchRequest(request: Request): void {
        for (const [name, scanner] of this.scanners) {
            if (scanner.onRequest) {
                void this.requestLimiter(async () => {
                    try {
                        await scanner.onRequest?.(request);
                    } catch (error) {
                        logger.debug(`Scanner "${name}" error in onRequest: ${error}`);
                    }
                });
            }
        }
    }

    /**
     * Dispatch response event to all scanners.
     */
    private dispatchResponse(response: Response): void {
        for (const [name, scanner] of this.scanners) {
            if (scanner.onResponse) {
                void this.responseLimiter(async () => {
                    try {
                        await scanner.onResponse?.(response);
                    } catch (error) {
                        logger.debug(`Scanner "${name}" error in onResponse: ${error}`);
                    }
                });
            }
        }
    }

    /**
     * Dispatch close event to all scanners.
     * Called by BrowserService during shutdown.
     */
    async dispatchClose(): Promise<void> {
        const promises: Promise<void>[] = [];

        for (const [name, scanner] of this.scanners) {
            if (scanner.onClose) {
                try {
                    const result = scanner.onClose();
                    if (result instanceof Promise) {
                        promises.push(result.catch(err => {
                            logger.error(`Scanner "${name}" error in onClose: ${err}`);
                        }));
                    }
                } catch (error) {
                    logger.error(`Scanner "${name}" error in onClose: ${error}`);
                }
            }
        }

        await Promise.all(promises);
        logger.debug(`Dispatched onClose to ${this.count} scanners`);
    }

    /**
     * Clear all scanner states.
     */
    clearAll(): void {
        for (const scanner of this.scanners.values()) {
            if (scanner.clear) {
                scanner.clear();
            }
        }
    }

    /**
     * Reset the registry (remove all scanners).
     */
    reset(): void {
        this.scanners.clear();
        this.context = null;
        this.page = null;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SINGLETON INSTANCE (optional - can also use dependency injection)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default scanner registry instance.
 * Use this for simple setups, or create your own instance for testing.
 */
export const defaultRegistry = new ScannerRegistry();

export default ScannerRegistry;
