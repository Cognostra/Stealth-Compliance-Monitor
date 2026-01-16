/**
 * BrowserService
 * 
 * Wraps Playwright to enforce human-like behavior and proxy all traffic through ZAP.
 * The raw Playwright page object is NEVER exposed publicly to enforce safety constraints.
 * 
 * REFACTORED: Now uses ScannerRegistry (Observer Pattern) instead of hardcoded scanner dependencies.
 */

import { chromium, Browser, BrowserContext, Page, Response, devices } from 'playwright';
import { getConfig, EnvConfig } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { ScannerRegistry, IScanner } from '../core/ScannerRegistry.js';
import { retryPlaywright } from '../utils/retry.js';
import { random, randomInt, isDeterministic } from '../utils/random.js';

// Default scanners (lazy-loaded for backward compatibility)
import { NetworkSpy, NetworkIncident } from './NetworkSpy.js';
import { SecretScanner, LeakedSecret } from './SecretScanner.js';
import { ConsoleMonitor } from './ConsoleMonitor.js';
import type { ConsoleError } from './ConsoleMonitor.js';
import { SupabaseSecurityScanner } from './SupabaseSecurityScanner.js';
import type { SupabaseSecurityIssue, SupabaseDetection } from './SupabaseSecurityScanner.js';
import { FrontendVulnerabilityScanner } from './FrontendVulnerabilityScanner.js';
import type { VulnerableLibrary } from './FrontendVulnerabilityScanner.js';

export type { ConsoleError }; // Re-export for compatibility with other services

/**
 * Navigation result returned by goto()
 */
export interface NavigationResult {
    url: string;
    status: number | null;
    ok: boolean;
    headers: Map<string, string>;
    timing: {
        started: number;
        finished: number;
        duration: number;
    };
}

/**
 * Element interaction result
 */
export interface InteractionResult {
    success: boolean;
    selector: string;
    action: string;
    error?: string;
}

/**
 * Screenshot result
 */
export interface ScreenshotResult {
    path: string;
    timestamp: number;
}

/**
 * BrowserService Class
 * 
 * Provides a safe wrapper around Playwright that:
 * - Enforces human-like delays between all actions
 * - Routes all traffic through ZAP proxy
 * - Never exposes the raw page object
 * - Handles cleanup properly
 * - Uses ScannerRegistry for plugin-style scanner management
 */
export class BrowserService {
    private static activeInstances: Set<BrowserService> = new Set();

    private browser: Browser | null = null;
    private context: BrowserContext | null = null;
    private page: Page | null = null;
    private config: EnvConfig;
    private isInitialized: boolean = false;
    private lastResponseHeaders: Map<string, string> = new Map();

    // Scanner Registry (Observer Pattern)
    private scannerRegistry: ScannerRegistry;

    // References to default scanners for backward compatibility
    private networkSpy: NetworkSpy | null = null;
    private secretScanner: SecretScanner | null = null;
    private consoleMonitor: ConsoleMonitor | null = null;
    private supabaseScanner: SupabaseSecurityScanner | null = null;
    private vulnScanner: FrontendVulnerabilityScanner | null = null;

    constructor(registry?: ScannerRegistry) {
        this.config = getConfig();
        this.scannerRegistry = registry || new ScannerRegistry();
        BrowserService.activeInstances.add(this);
    }

    /**
     * Register a scanner with the service.
     * Call this BEFORE initialize() to add custom scanners.
     */
    registerScanner(scanner: IScanner): void {
        this.scannerRegistry.register(scanner);
    }

    /**
     * Get the scanner registry for advanced access
     */
    getRegistry(): ScannerRegistry {
        return this.scannerRegistry;
    }

    /**
     * Register default scanners (called automatically during initialize)
     */
    private registerDefaultScanners(): void {
        // Only register if not already registered
        if (!this.scannerRegistry.getScanner('NetworkSpy')) {
            this.networkSpy = new NetworkSpy();
            this.scannerRegistry.register(this.networkSpy);
        } else {
            this.networkSpy = this.scannerRegistry.getScanner('NetworkSpy') as NetworkSpy;
        }

        if (!this.scannerRegistry.getScanner('SecretScanner')) {
            this.secretScanner = new SecretScanner();
            this.scannerRegistry.register(this.secretScanner);
        } else {
            this.secretScanner = this.scannerRegistry.getScanner('SecretScanner') as SecretScanner;
        }

        if (!this.scannerRegistry.getScanner('ConsoleMonitor')) {
            this.consoleMonitor = new ConsoleMonitor();
            this.scannerRegistry.register(this.consoleMonitor);
        } else {
            this.consoleMonitor = this.scannerRegistry.getScanner('ConsoleMonitor') as ConsoleMonitor;
        }

        if (!this.scannerRegistry.getScanner('SupabaseSecurityScanner')) {
            this.supabaseScanner = new SupabaseSecurityScanner();
            this.scannerRegistry.register(this.supabaseScanner);
        } else {
            this.supabaseScanner = this.scannerRegistry.getScanner('SupabaseSecurityScanner') as SupabaseSecurityScanner;
        }

        if (!this.scannerRegistry.getScanner('FrontendVulnerabilityScanner')) {
            this.vulnScanner = new FrontendVulnerabilityScanner();
            this.scannerRegistry.register(this.vulnScanner);
        } else {
            this.vulnScanner = this.scannerRegistry.getScanner('FrontendVulnerabilityScanner') as FrontendVulnerabilityScanner;
        }
    }

    /**
     * Get the configured User-Agent string
     */
    private getUserAgent(): string {
        return this.config.USER_AGENT || 'ComplianceMonitor/1.0 (HealthCheck)';
    }

    /**
     * Human-like delay between actions
     * Returns a promise that resolves after a random time between 2000ms and 5000ms
     * This is a PRIVATE enforcement mechanism - all public methods must call this
     */
    private async humanDelay(): Promise<number> {
        const minDelay = this.config.MIN_DELAY_MS || 2000;
        const maxDelay = this.config.MAX_DELAY_MS || 5000;
        const delay = randomInt(minDelay, maxDelay);

        logger.debug(`Human delay: waiting ${delay}ms before next action`);
        await new Promise(resolve => setTimeout(resolve, delay));

        return delay;
    }

    /**
     * Initialize the browser with ZAP proxy and stealth settings
     * Must be called before any other methods
     */
    /**
     * Initialize the browser with ZAP proxy and stealth settings
     * Must be called before any other methods
     */
    async initialize(options?: { 
        headless?: boolean; 
        useProxy?: boolean; 
        deviceName?: string;
        slowMo?: number;
        devtools?: boolean;
    }): Promise<void> {
        if (this.browser) {
            logger.warn('BrowserService already initialized');
            return;
        }

        // Get debug settings from config (can be overridden by options)
        const debugConfig = {
            headed: this.config.DEBUG_HEADED,
            slowMo: this.config.DEBUG_SLOW_MO,
            devtools: this.config.DEBUG_DEVTOOLS,
            captureConsole: this.config.DEBUG_CAPTURE_CONSOLE,
        };

        // Determine final settings (CLI options override env config)
        const headless = options?.headless ?? !debugConfig.headed;
        const useProxy = options?.useProxy ?? true;
        const deviceName = options?.deviceName;
        const slowMo = options?.slowMo ?? debugConfig.slowMo;
        const devtools = options?.devtools ?? debugConfig.devtools;
        const enableStealth = (getConfig() as any).stealth !== false; // Default true

        // Register default scanners before initialization
        this.registerDefaultScanners();

        let userAgent = this.getUserAgent();
        let viewport: { width: number; height: number } | null = { width: 1920, height: 1080 };
        let deviceConfig: any = {};

        // Device Emulation vs Desktop Stealth
        if (deviceName && deviceName !== 'desktop') {
            const device = devices[deviceName];
            if (device) {
                logger.info(`📱 Emulating device: ${deviceName}`);
                deviceConfig = device;
                userAgent = device.userAgent;
                viewport = device.viewport;
            } else {
                logger.warn(`Device '${deviceName}' not found in Playwright defaults. Falling back to desktop.`);
            }
        }

        // Only apply random stealth variation if NOT emulating a specific device (to avoid breaking emulation)
        if (enableStealth && (!deviceName || deviceName === 'desktop')) {
            const userAgents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
            ];
            userAgent = userAgents[Math.floor(random() * userAgents.length)];

            // Randomize viewport slightly (+/- 20px)
            if (!isDeterministic()) {
                viewport = {
                    width: 1920 + randomInt(-20, 20),
                    height: 1080 + randomInt(-20, 20)
                };
            }
        }

        logger.info('Initializing BrowserService...');
        logger.info(`Headless: ${headless}`);
        if (useProxy) logger.info(`Proxy: ${this.config.ZAP_PROXY_URL}`);
        logger.info(`Stealth Mode: ${enableStealth}`);
        if (slowMo > 0) logger.info(`SlowMo: ${slowMo}ms`);
        if (devtools) logger.info(`DevTools: enabled`);
        logger.info(`User-Agent: ${userAgent}`);
        logger.info(`Registered Scanners: ${this.scannerRegistry.getScannerNames().join(', ')}`);

        try {
            // Launch browser with proxy configuration
            this.browser = await chromium.launch({
                headless,
                slowMo: slowMo > 0 ? slowMo : undefined,
                devtools: devtools && !headless, // devtools only works in headed mode
                args: [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    ...(enableStealth ? ['--disable-infobars', '--exclude-switches=enable-automation'] : [])
                ],
            });

            const contextOptions: any = {
                userAgent: userAgent,
                ignoreHTTPSErrors: true,
                viewport: viewport,
                locale: 'en-US',
                timezoneId: 'America/Chicago',
                javaScriptEnabled: true,
                hasTouch: false,
                isMobile: false,
                ...deviceConfig // Override with device specifics (isMobile, hasTouch, dpi, etc.)
            };

            // Route all traffic through ZAP proxy if enabled
            if (useProxy) {
                contextOptions.proxy = {
                    server: this.config.ZAP_PROXY_URL,
                };
            }

            // Create context with proxy, custom UA, and cert bypass
            this.context = await this.browser.newContext(contextOptions);

            // STEALTH: Inject evasions to delete navigator.webdriver
            if (enableStealth) {
                await this.context.addInitScript(() => {
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                    });

                    // Mock plugins (simplistic)
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5],
                    });

                    // Mock languages
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                    });
                });
            }

            // Dispatch context created event to all scanners
            await this.scannerRegistry.dispatchContextCreated(this.context);

            // Create the page
            this.page = await this.context.newPage();

            // Dispatch page created event to all scanners
            await this.scannerRegistry.dispatchPageCreated(this.page);

            // Capture response headers for security analysis
            this.page.on('response', (response: Response) => {
                // Only capture headers from the target domain
                if (response.url().startsWith(this.config.LIVE_URL)) {
                    const headers = response.headers();
                    this.lastResponseHeaders.clear();
                    Object.entries(headers).forEach(([name, value]) => {
                        this.lastResponseHeaders.set(name.toLowerCase(), value);
                    });
                }
            });

            this.isInitialized = true;
            logger.info(`BrowserService initialized with ${this.scannerRegistry.count} scanners`);
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`Failed to initialize browser: ${errMsg}`);
            await this.close();
            throw new Error(`BrowserService initialization failed: ${errMsg}`);
        }
    }

    /**
     * Ensure the browser is initialized before any action
     */
    private ensureInitialized(): void {
        if (!this.isInitialized || !this.page) {
            throw new Error(
                'BrowserService not initialized. Call initialize() before using any methods.'
            );
        }
    }

    /**
     * Navigate to a URL with enforced human delay and retry logic
     * @param url - The URL to navigate to
     * @returns Navigation result with status and headers
     */
    async goto(url: string): Promise<NavigationResult> {
        this.ensureInitialized();
        await this.humanDelay();

        const started = Date.now();
        logger.debug(`Navigating to: ${url}`);

        try {
            const response = await retryPlaywright(
                () => this.page!.goto(url, {
                    waitUntil: 'domcontentloaded',
                    timeout: 60000,
                }),
                { retries: 3, baseDelay: 1000, logger }
            );

            const finished = Date.now();

            const result: NavigationResult = {
                url: this.page!.url(),
                status: response?.status() ?? null,
                ok: response?.ok() ?? false,
                headers: new Map(Object.entries(response?.headers() ?? {})),
                timing: {
                    started,
                    finished,
                    duration: finished - started,
                },
            };

            logger.debug(`Navigation complete: ${result.status} in ${result.timing.duration}ms`);
            return result;
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`Navigation failed after retries: ${errMsg}`);
            throw error;
        }
    }

    /**
     * Fill an input field with text (with human-like behavior)
     * @param selector - CSS selector for the input
     * @param text - Text to type
     * @returns Interaction result
     */
    async fill(selector: string, text: string): Promise<InteractionResult> {
        this.ensureInitialized();
        await this.humanDelay();

        try {
            await this.page!.fill(selector, text);
            logger.debug(`Filled input '${selector}' with text`);
            return { success: true, selector, action: 'fill' };
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.warn(`Fill failed for '${selector}': ${errMsg}`);
            return { success: false, selector, action: 'fill', error: errMsg };
        }
    }

    /**
     * Type into an input field keystroke-by-keystroke (with human-like delays)
     * @param selector - CSS selector for the input
     * @param text - Text to type
     * @param delay - Delay between keystrokes (default 75ms)
     * @returns Interaction result
     */
    async type(selector: string, text: string, delay = 75): Promise<InteractionResult> {
        this.ensureInitialized();
        await this.humanDelay();

        try {
            await this.page!.type(selector, text, { delay });
            logger.debug(`Typed into '${selector}'`);
            return { success: true, selector, action: 'type' };
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.warn(`Type failed for '${selector}': ${errMsg}`);
            return { success: false, selector, action: 'type', error: errMsg };
        }
    }

    /**
     * Click an element (with human-like behavior and retry logic)
     * @param selector - CSS selector for the element
     * @returns Interaction result
     */
    async click(selector: string): Promise<InteractionResult> {
        this.ensureInitialized();
        await this.humanDelay();

        try {
            await retryPlaywright(
                () => this.page!.click(selector),
                { retries: 2, baseDelay: 500, logger }
            );
            logger.debug(`Clicked element: ${selector}`);
            return { success: true, selector, action: 'click' };
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.warn(`Click failed for '${selector}': ${errMsg}`);
            return { success: false, selector, action: 'click', error: errMsg };
        }
    }

    /**
     * Wait for a selector to appear on the page
     * @param selector - CSS selector to wait for
     * @param timeout - Maximum time to wait (default 30s)
     * @returns Whether the element was found
     */
    async waitForSelector(selector: string, timeout = 30000): Promise<boolean> {
        this.ensureInitialized();

        try {
            await this.page!.waitForSelector(selector, { timeout });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Wait for navigation to complete
     */
    async waitForNavigation(timeout = 30000): Promise<void> {
        this.ensureInitialized();
        await this.page!.waitForLoadState('domcontentloaded', { timeout });
    }

    /**
     * Get the current page URL
     */
    getCurrentUrl(): string {
        this.ensureInitialized();
        return this.page!.url();
    }

    /**
     * Get the page title
     */
    async getTitle(): Promise<string> {
        this.ensureInitialized();
        return this.page!.title();
    }

    /**
     * Check if an element exists on the page
     * @param selector - CSS selector to check
     */
    async exists(selector: string): Promise<boolean> {
        this.ensureInitialized();
        const element = await this.page!.$(selector);
        return element !== null;
    }

    /**
     * Alias for exists() - backward compatibility
     * @param selector - CSS selector to check
     */
    async elementExists(selector: string): Promise<boolean> {
        return this.exists(selector);
    }

    /**
     * Get text content of an element
     * @param selector - CSS selector
     */
    async getText(selector: string): Promise<string | null> {
        this.ensureInitialized();
        try {
            return await this.page!.textContent(selector);
        } catch {
            return null;
        }
    }

    /**
     * Take a screenshot
     * @param name - Screenshot filename (without extension)
     * @returns Screenshot result with path
     */
    async screenshot(name: string): Promise<ScreenshotResult> {
        this.ensureInitialized();

        const timestamp = Date.now();
        const filename = `${name}-${timestamp}.png`;
        const filepath = `${this.config.SCREENSHOTS_DIR}/${filename}`;

        await this.page!.screenshot({ path: filepath, fullPage: true });
        logger.debug(`Screenshot saved: ${filepath}`);

        return { path: filepath, timestamp };
    }

    /**
     * Get the last captured response headers
     * Used for security header analysis
     */
    getLastResponseHeaders(): Map<string, string> {
        return new Map(this.lastResponseHeaders);
    }

    /**
     * Count the number of elements matching a selector
     * Used for data integrity checks (e.g. counting attachments)
     */
    async countElements(selector: string): Promise<number> {
        this.ensureInitialized();
        try {
            // Using $$eval is efficient as it runs within the page context
            const count = await this.page!.$$eval(selector, (elements) => elements.length);
            return count;
        } catch (error) {
            logger.debug(`Failed to count elements for selector '${selector}': ${error}`);
            return 0;
        }
    }

    /**
     * Get all links (anchor hrefs) from the current page
     * Used by CrawlerService for link discovery
     */
    async getAllLinks(): Promise<string[]> {
        this.ensureInitialized();

        try {
            const links = await this.page!.evaluate(() => {
                const anchors = document.querySelectorAll('a[href]');
                return Array.from(anchors)
                    .map(a => (a as HTMLAnchorElement).href)
                    .filter(href => href && href.startsWith('http'));
            });
            return links;
        } catch (error) {
            logger.warn('Failed to get links from page');
            return [];
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Scanner Result Accessors (Backward Compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Get collected console errors
     */
    getConsoleErrors(): ConsoleError[] {
        return this.consoleMonitor?.getErrors() ?? [];
    }

    /**
     * Clear collected console errors
     */
    clearConsoleErrors(): void {
        this.consoleMonitor?.clear();
    }

    /**
     * Get console errors for a specific URL
     */
    getConsoleErrorsForUrl(url: string): ConsoleError[] {
        return this.consoleMonitor?.getErrorsForUrl(url) ?? [];
    }

    /**
     * Check if browser is initialized and ready
     */
    isReady(): boolean {
        return this.isInitialized && this.browser !== null && this.page !== null;
    }

    /**
     * Get the current Playwright page instance
     * Warning: Use with caution to maintain encapsulation
     */
    getPage(): Page | null {
        return this.page;
    }

    /**
     * Get recorded network incidents
     */
    getNetworkIncidents(): NetworkIncident[] {
        return this.networkSpy?.getIncidents() ?? [];
    }

    /**
     * Get detected leaked secrets
     */
    getLeakedSecrets(): LeakedSecret[] {
        return this.secretScanner?.getSecrets() ?? [];
    }

    /**
     * Get Supabase security scan results
     */
    getSupabaseResults(): SupabaseDetection {
        return this.supabaseScanner?.getResults() ?? {
            detected: false,
            issues: []
        };
    }

    /**
     * Get Supabase security issues only
     */
    getSupabaseIssues(): SupabaseSecurityIssue[] {
        return this.supabaseScanner?.getIssues() ?? [];
    }

    /**
     * Run active Supabase security tests (RLS probes, storage checks)
     */
    async runSupabaseSecurityTests(): Promise<void> {
        if (this.page && this.supabaseScanner) {
            await this.supabaseScanner.runActiveTests(this.page);
        }
    }

    /**
     * Get detected vulnerable frontend libraries
     */
    getVulnerableLibraries(): VulnerableLibrary[] {
        return this.vulnScanner?.getVulnerableLibraries() ?? [];
    }

    /**
     * Scan page globals for library versions (call after page load)
     */
    async scanPageLibraries(): Promise<void> {
        if (this.page && this.vulnScanner) {
            await this.vulnScanner.scanPageGlobals(this.page);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Parallel Page Management (for CrawlerService)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Add cookies to the browser context
     * Used for session injection / auth bypass
     */
    async addCookies(cookies: Array<{
        name: string;
        value: string;
        url?: string;
        domain?: string;
        path?: string;
        expires?: number;
        httpOnly?: boolean;
        secure?: boolean;
        sameSite?: "Strict" | "Lax" | "None";
    }>): Promise<void> {
        this.ensureInitialized();
        if (this.context) {
            await this.context.addCookies(cookies);
            logger.debug(`Added ${cookies.length} cookies to context`);
        }
    }

    /**
     * Get the browser context for creating new pages
     * Used by CrawlerService for parallel page execution
     */
    getContext(): BrowserContext | null {
        return this.context;
    }

    /**
     * Create a new isolated page (tab) for parallel execution
     * Each page is independent and can be used concurrently
     * @returns New Page instance
     */
    async createNewPage(): Promise<Page> {
        this.ensureInitialized();

        if (!this.context) {
            throw new Error('Browser context not available');
        }

        const newPage = await this.context.newPage();

        // Dispatch page created event to all scanners for this new page
        await this.scannerRegistry.dispatchPageCreated(newPage);

        logger.debug('Created new page for parallel execution');
        return newPage;
    }

    /**
     * Close a specific page
     * @param page - Page instance to close
     */
    async closePage(page: Page): Promise<void> {
        try {
            await page.close();
            logger.debug('Closed parallel page');
        } catch (error) {
            logger.debug(`Failed to close page: ${error}`);
        }
    }

    /**
     * Get the minimum delay value for human-like behavior
     */
    getMinDelay(): number {
        return this.config.MIN_DELAY_MS || 2000;
    }

    /**
     * Get the maximum delay value for human-like behavior
     */
    getMaxDelay(): number {
        return this.config.MAX_DELAY_MS || 5000;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Debug Mode Features
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Capture error state: screenshot + console logs
     * Useful for debugging failures in headful or headless mode
     * @param errorName - Name/description of the error
     * @returns Object with screenshot path and console errors
     */
    async captureErrorState(errorName: string): Promise<{
        screenshotPath: string | null;
        consoleErrors: ConsoleError[];
        allConsoleLogs: ConsoleError[];
        currentUrl: string;
        timestamp: number;
    }> {
        const timestamp = Date.now();
        let screenshotPath: string | null = null;
        
        // Capture screenshot
        if (this.page && this.isInitialized) {
            try {
                const filename = `error-${errorName.replace(/[^a-zA-Z0-9]/g, '-')}-${timestamp}.png`;
                const filepath = `${this.config.SCREENSHOTS_DIR}/${filename}`;
                await this.page.screenshot({ path: filepath, fullPage: true });
                screenshotPath = filepath;
                logger.info(`📸 Error screenshot saved: ${filepath}`);
            } catch (e) {
                logger.warn(`Failed to capture error screenshot: ${e}`);
            }
        }

        // Get console errors and all logs
        const consoleErrors = this.getConsoleErrors();
        const allConsoleLogs = this.config.DEBUG_CAPTURE_CONSOLE 
            ? (this.consoleMonitor?.getErrors() ?? [])
            : consoleErrors;

        const currentUrl = this.page?.url() ?? 'unknown';

        return {
            screenshotPath,
            consoleErrors,
            allConsoleLogs,
            currentUrl,
            timestamp,
        };
    }

    /**
     * Pause execution for debugging (only works in headed mode)
     * Opens a REPL-like pause - press "Resume" in browser to continue
     */
    async debugPause(reason: string = 'Debug pause'): Promise<void> {
        if (!this.page || !this.isInitialized) {
            logger.warn('Cannot pause: browser not initialized');
            return;
        }

        const isHeaded = !this.browser?.contexts()[0]?.browser()?.isConnected?.() === false;
        
        if (this.config.DEBUG_PAUSE_ON_FAILURE || this.config.DEBUG_HEADED) {
            logger.info(`⏸️  Pausing: ${reason}`);
            logger.info('   Press "Resume" in the browser DevTools or Ctrl+C to continue...');
            
            try {
                // Use Playwright's built-in pause (opens inspector)
                await this.page.pause();
            } catch (e) {
                // Pause may throw if not in headed mode
                logger.debug(`Pause not available: ${e}`);
            }
        }
    }

    /**
     * Check if debug mode is enabled
     */
    isDebugMode(): boolean {
        return this.config.DEBUG_HEADED || 
               this.config.DEBUG_DEVTOOLS || 
               this.config.DEBUG_PAUSE_ON_FAILURE ||
               this.config.DEBUG_SLOW_MO > 0;
    }

    /**
     * Properly shut down the browser context and browser
     * Always call this when done to prevent resource leaks
     */
    async close(): Promise<void> {
        logger.info('Closing BrowserService...');

        try {
            // Dispatch close event to all scanners
            await this.scannerRegistry.dispatchClose();

            if (this.page) {
                await this.page.close().catch(() => { });
                this.page = null;
            }

            if (this.context) {
                await this.context.close().catch(() => { });
                this.context = null;
            }

            if (this.browser) {
                await this.browser.close().catch(() => { });
                this.browser = null;
            }

            this.isInitialized = false;
            this.lastResponseHeaders.clear();

            BrowserService.activeInstances.delete(this);

            logger.info('BrowserService closed successfully');
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`Error during browser cleanup: ${errMsg}`);
        }
    }

    /**
     * Static helper to close all active browser sessions
     * Essential for graceful shutdown handling
     */
    static async closeAll(): Promise<void> {
        const instances = Array.from(this.activeInstances);
        if (instances.length === 0) return;

        logger.info(`Shutting down ${instances.length} active browser session(s)...`);
        await Promise.all(instances.map(instance => instance.close()));
    }
}

export default BrowserService;
