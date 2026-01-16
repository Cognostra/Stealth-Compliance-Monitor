/**
 * Custom Check Loader
 * 
 * Dynamically loads and executes user-defined compliance checks from the
 * custom_checks/ directory. Each check file exports a check function that
 * receives the Playwright page and context.
 * 
 * Features:
 * - Supports .ts and .js check files
 * - Async check execution with timeout
 * - Error isolation (one check failure doesn't affect others)
 * - Results aggregation for reporting
 */

import * as fs from 'fs';
import * as path from 'path';
import { Page, BrowserContext } from 'playwright';
import { Logger } from '../types/index.js';

/**
 * Result of a single custom check
 */
export interface CustomCheckViolation {
    /** Unique check ID (e.g., 'cookie-consent-missing') */
    id: string;
    /** Human-readable title */
    title: string;
    /** Severity level */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    /** Detailed description of the issue */
    description: string;
    /** Element selector (if applicable) */
    selector?: string;
    /** URL where the issue was found */
    url?: string;
    /** Remediation guidance */
    remediation?: string;
    /** Additional evidence or context */
    evidence?: string;
}

/**
 * Return type from a custom check function
 */
export interface CustomCheckResult {
    /** Check name */
    name: string;
    /** Pass/fail status */
    passed: boolean;
    /** List of violations found */
    violations: CustomCheckViolation[];
    /** Execution duration in ms */
    duration: number;
    /** Error message if check failed to execute */
    error?: string;
}

/**
 * Context passed to custom check functions
 */
export interface CustomCheckContext {
    /** Target URL being scanned */
    targetUrl: string;
    /** Current page URL */
    currentUrl: string;
    /** All visited URLs so far */
    visitedUrls: string[];
    /** Logger for debug output */
    logger: Logger;
    /** Profile name */
    profile: string;
}

/**
 * Signature for custom check functions
 */
export type CustomCheckFunction = (
    page: Page,
    context: CustomCheckContext
) => Promise<CustomCheckViolation[]>;

/**
 * Loaded check module
 */
interface LoadedCheck {
    name: string;
    filePath: string;
    check: CustomCheckFunction;
}

/**
 * Custom Check Loader service
 */
export class CustomCheckLoader {
    private readonly logger: Logger;
    private readonly checksDir: string;
    private readonly timeout: number;
    private loadedChecks: LoadedCheck[] = [];
    private isLoaded: boolean = false;

    constructor(
        logger: Logger,
        checksDir: string = './custom_checks',
        timeout: number = 30000
    ) {
        this.logger = logger;
        this.checksDir = path.resolve(checksDir);
        this.timeout = timeout;
    }

    /**
     * Load all check files from the custom_checks directory
     */
    async loadChecks(): Promise<number> {
        if (this.isLoaded) {
            return this.loadedChecks.length;
        }

        // Check if directory exists
        if (!fs.existsSync(this.checksDir)) {
            this.logger.debug(`Custom checks directory not found: ${this.checksDir}`);
            this.isLoaded = true;
            return 0;
        }

        // Find all .ts and .js files (excluding .d.ts)
        const files = fs.readdirSync(this.checksDir).filter(file => {
            const ext = path.extname(file);
            return (ext === '.ts' || ext === '.js') && !file.endsWith('.d.ts');
        });

        this.logger.info(`Found ${files.length} custom check files`);

        for (const file of files) {
            const filePath = path.join(this.checksDir, file);
            const checkName = path.basename(file, path.extname(file));

            try {
                // Dynamic import (works for both TS with ts-node and compiled JS)
                const module = await import(filePath);

                let checkFn: CustomCheckFunction | undefined;

                // Handle different export patterns (ESM vs CJS)
                if (typeof module.default === 'function') {
                    // export default async function(...)
                    checkFn = module.default;
                } else if (module.default && typeof module.default.check === 'function') {
                    // module.exports = { check: ... } (CJS default export is the exports object)
                    checkFn = module.default.check;
                } else if (typeof module.check === 'function') {
                    // export async function check(...)
                    checkFn = module.check;
                }

                if (!checkFn) {
                    this.logger.warn(`Custom check '${checkName}' does not export a 'check' function or default function`);
                    continue;
                }

                this.loadedChecks.push({
                    name: checkName,
                    filePath,
                    check: checkFn
                });

                this.logger.debug(`Loaded custom check: ${checkName}`);

            } catch (error) {
                this.logger.error(`Failed to load custom check '${checkName}': ${error instanceof Error ? error.message : String(error)}`);
            }
        }

        this.isLoaded = true;
        this.logger.info(`Loaded ${this.loadedChecks.length} custom checks`);

        return this.loadedChecks.length;
    }

    /**
     * Execute all loaded checks against a page
     */
    async runChecks(
        page: Page,
        context: CustomCheckContext
    ): Promise<CustomCheckResult[]> {
        if (!this.isLoaded) {
            await this.loadChecks();
        }

        const results: CustomCheckResult[] = [];

        for (const loadedCheck of this.loadedChecks) {
            const result = await this.executeCheck(loadedCheck, page, context);
            results.push(result);
        }

        return results;
    }

    /**
     * Execute a single check with timeout and error handling
     */
    private async executeCheck(
        loadedCheck: LoadedCheck,
        page: Page,
        context: CustomCheckContext
    ): Promise<CustomCheckResult> {
        const startTime = Date.now();

        try {
            // Execute with timeout
            const violations = await Promise.race([
                loadedCheck.check(page, context),
                new Promise<CustomCheckViolation[]>((_, reject) =>
                    setTimeout(() => reject(new Error('Check timeout')), this.timeout)
                )
            ]);

            const duration = Date.now() - startTime;

            return {
                name: loadedCheck.name,
                passed: violations.length === 0,
                violations: violations.map(v => ({
                    ...v,
                    url: v.url || context.currentUrl
                })),
                duration
            };

        } catch (error) {
            const duration = Date.now() - startTime;
            const errorMsg = error instanceof Error ? error.message : String(error);

            this.logger.error(`Custom check '${loadedCheck.name}' failed: ${errorMsg}`);

            return {
                name: loadedCheck.name,
                passed: false,
                violations: [],
                duration,
                error: errorMsg
            };
        }
    }

    /**
     * Get list of loaded check names
     */
    getLoadedCheckNames(): string[] {
        return this.loadedChecks.map(c => c.name);
    }

    /**
     * Check if any checks are loaded
     */
    hasChecks(): boolean {
        return this.loadedChecks.length > 0;
    }

    /**
     * Get the number of loaded checks
     */
    getCheckCount(): number {
        return this.loadedChecks.length;
    }

    /**
     * Clear loaded checks (useful for testing)
     */
    clear(): void {
        this.loadedChecks = [];
        this.isLoaded = false;
    }
}

export default CustomCheckLoader;
