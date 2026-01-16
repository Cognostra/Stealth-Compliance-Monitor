/**
 * CrawlerService
 * 
 * Intelligently navigates the site to discover and verify high-value pages.
 * All traffic flows through ZAP proxy for passive security analysis.
 * 
 * REFACTORED: Now uses Producer-Consumer pattern with bounded concurrency
 * for parallel page processing.
 * 
 * Features:
 * - Parallel page processing (configurable concurrency)
 * - Link discovery from homepage/dashboard
 * - Prioritizes important pages (meta, weapon, loadout, game)
 * - Ignores generic links (privacy, terms, login)
 * - Content validation with error detection
 * - Console error monitoring
 * - Automatic screenshots on suspicious pages
 * - Visual Regression Testing (VisualSentinel)
 * - Isolated page tabs for each parallel task
 */

import pLimit from 'p-limit';
import { Page } from 'playwright';
import { BrowserService, ConsoleError } from './BrowserService';
import { VisualSentinel, VisualTestResult } from './VisualSentinel';
import { AssetValidator, AssetCheckResult } from './AssetValidator';
import { LinkChecker, LinkCheckResult } from './LinkChecker';
import { SEOValidator, SEOResult } from './SEOValidator';
import { InteractionTester, InteractionTestResult } from './InteractionTester';
import { ResilienceTester, ResilienceCheckResult } from './ResilienceTester';
import { A11yScanner, A11yResult } from './A11yScanner';
import { PersistenceService } from './PersistenceService';
import { EnvConfig } from '../config/env';
import { ComplianceConfig } from '../config/compliance.config';
import { logger } from '../utils/logger';

/**
 * Content validation result
 */
export interface ContentValidation {
    valid: boolean;
    length: number;
    hasErrorIndicator: boolean;
    errorIndicatorFound?: string;
    hasStuckSpinner: boolean;
    consoleErrors: ConsoleError[];
    screenshotPath?: string;
}

/**
 * Crawl result for a single page
 */
export interface PageCrawlResult {
    url: string;
    status: number | null;
    title: string;
    contentValid: boolean;
    contentLength: number;
    linksFound: number;
    duration: number;
    error?: string;
    validation: ContentValidation;
    visualResult?: VisualTestResult;
    assetResult?: AssetCheckResult;
    linkCheckResult?: LinkCheckResult;
    seoResult?: SEOResult;
    interactionResult?: InteractionTestResult;
    resilienceResult?: ResilienceCheckResult;
    a11yResult?: A11yResult;
}

/**
 * Full crawl session result
 */
export interface CrawlSessionResult {
    startUrl: string;
    pagesVisited: number;
    pageResults: PageCrawlResult[];
    highValueLinksFound: number;
    failedPages: number;
    suspiciousPages: number;
    totalConsoleErrors: number;
    totalDuration: number;
    timestamp: string;
    concurrency: number;
}

/**
 * Link priority configuration
 */
interface LinkConfig {
    priorityKeywords: string[];
    ignorePaths: string[];
    maxPages: number;
    minContentLength: number;
    contentSelectors: string[];
    errorIndicators: string[];
    spinnerSelectors: string[];
    spinnerTimeout: number;
    concurrency: number;
    depth?: number;
    excludePatterns?: string[];
    enableVisualRegression?: boolean;
}

/**
 * Default configuration - generic patterns that work across most web apps
 */
const DEFAULT_LINK_CONFIG: LinkConfig = {
    enableVisualRegression: true,
    priorityKeywords: [
        // User content pages
        '/profile', '/user', '/u/',
        // Core app pages
        '/dashboard', '/gallery', '/explore', '/discover', '/browse',
        // Content detail pages
        '/loadout', '/post', '/item', '/detail', '/view',
        // Settings/account (important for auth flow testing)
        '/settings', '/account', '/preferences',
        // Game-specific (loadout.app)
        '/meta', '/weapon', '/build', '/class', '/attachment', '/game',
    ],
    ignorePaths: ['/privacy', '/terms', '/login', '/logout', '/signup', '/register', '/auth', '/api', '#', 'javascript:', 'mailto:', '/cdn-cgi'],
    maxPages: 15,
    minContentLength: 500,
    contentSelectors: [
        '.loadout-container',
        '.weapon-container',
        '.meta-container',
        '.build-container',
        '.content-container',
        'main',
        '[role="main"]',
        '#main-content',
        '.main-content',
        'article',
    ],
    // Error indicators that suggest data failed to load
    errorIndicators: [
        'No loadouts found',
        'Error loading data',
        'undefined is not',
        'TypeError: undefined',
        '[object Undefined]',
        'Something went wrong',
        'Failed to load',
        'Error occurred',
        'Unable to load',
        'Data not available',
        ': null,',  // JSON rendering null values
        ': NaN,',   // JSON rendering NaN values
    ],
    // Selectors for loading spinners
    spinnerSelectors: [
        '.loading',
        '.spinner',
        '.loader',
        '[class*="loading"]',
        '[class*="spinner"]',
        '.sk-spinner',
        '.lds-ring',
        '[data-loading="true"]',
    ],
    spinnerTimeout: 5000, // 5 seconds
    concurrency: 3, // Default parallel page limit
};

/**
 * CrawlerService Class
 * 
 * Discovers and verifies high-value pages with content validation.
 * Uses Producer-Consumer pattern for parallel URL processing.
 */
export class CrawlerService {
    private readonly browserService: BrowserService;
    private readonly visualSentinel: VisualSentinel;
    private readonly assetValidator: AssetValidator;
    private readonly linkChecker: LinkChecker;
    private readonly seoValidator: SEOValidator;
    private readonly interactionTester: InteractionTester;
    private readonly resilienceTester: ResilienceTester;
    private readonly a11yScanner: A11yScanner;
    private readonly config: ComplianceConfig;
    private readonly linkConfig: LinkConfig;

    // Thread-safe state management
    private visitedUrls: Set<string> = new Set();
    private urlQueue: string[] = [];
    private allConsoleErrors: ConsoleError[] = [];
    private pageResults: PageCrawlResult[] = [];

    // Test counters (atomic operations)
    private searchTestsRun: number = 0;
    private resilienceTestsRun: number = 0;
    private a11yTestsRun: number = 0;

    // Concurrency limiter
    private limit: ReturnType<typeof pLimit> | null = null;

    // Write-Ahead Logging for crash resilience
    private persistence: PersistenceService | null = null;

    constructor(browserService: BrowserService, config: ComplianceConfig, linkConfig?: Partial<LinkConfig>) {
        this.browserService = browserService;
        this.visualSentinel = new VisualSentinel();
        this.assetValidator = new AssetValidator();
        this.linkChecker = new LinkChecker();
        this.seoValidator = new SEOValidator();
        this.interactionTester = new InteractionTester();
        this.resilienceTester = new ResilienceTester();
        this.a11yScanner = new A11yScanner();
        this.config = config;

        // Merge config with defaults, preferring passed config values
        this.linkConfig = {
            ...DEFAULT_LINK_CONFIG,
            concurrency: config.concurrency,
            maxPages: config.maxPages,
            ...linkConfig
        };

        // Map excludePatterns to ignorePaths if provided
        if (linkConfig?.excludePatterns) {
            this.linkConfig.ignorePaths = [
                ...this.linkConfig.ignorePaths,
                ...linkConfig.excludePatterns
            ];
        }
    }

    /**
     * Human-like delay between actions (for parallel pages)
     */
    private async humanDelay(): Promise<void> {
        const minDelay = this.browserService.getMinDelay();
        const maxDelay = this.browserService.getMaxDelay();
        const delay = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;
        await new Promise(resolve => setTimeout(resolve, delay));
    }

    /**
     * Run the full crawl session with parallel processing
     */
    async crawl(startUrl?: string): Promise<CrawlSessionResult> {
        const baseUrl = startUrl || this.config.LIVE_URL;
        const startTime = Date.now();
        const concurrency = this.linkConfig.concurrency;

        logger.info('═'.repeat(60));
        logger.info('CRAWLER SERVICE - Starting (Parallel Mode)');
        logger.info('═'.repeat(60));
        logger.info(`Base URL: ${baseUrl}`);
        logger.info(`Max pages: ${this.linkConfig.maxPages}`);
        logger.info(`Concurrency: ${concurrency} parallel pages`);
        logger.info(`Error indicators: ${this.linkConfig.errorIndicators.length} patterns`);
        logger.info('');

        // Reset state
        this.visitedUrls.clear();
        this.urlQueue = [];
        this.allConsoleErrors = [];
        this.pageResults = [];
        this.searchTestsRun = 0;
        this.resilienceTestsRun = 0;
        this.a11yTestsRun = 0;

        // Initialize concurrency limiter
        this.limit = pLimit(concurrency);

        // Initialize Write-Ahead Logging
        this.persistence = new PersistenceService();
        await this.persistence.init(baseUrl);
        logger.info(`WAL Session: ${this.persistence.getSessionId()}`);

        try {
            // Phase 1: Discover links from homepage (single page, blocking)
            logger.info('Phase 1: Discovering links from homepage...');
            const homeResult = await this.visitPage(baseUrl, true);
            this.pageResults.push(homeResult);

            // Log homepage result to WAL immediately
            await this.persistence.log('page_result', homeResult);

            // Collect initial links
            const discoveredLinks = await this.discoverLinksFromPage(
                this.browserService.getPage()!
            );
            const highValueLinks = this.filterHighValueLinks(discoveredLinks);

            for (const link of highValueLinks) {
                const normalized = this.normalizeUrl(link);
                if (!this.visitedUrls.has(normalized)) {
                    this.urlQueue.push(link);
                }
            }

            logger.info(`Found ${this.urlQueue.length} high-value URLs to crawl`);
            logger.info('');

            // Phase 2: Parallel crawl of discovered URLs
            logger.info('Phase 2: Parallel crawling high-value pages...');

            await this.parallelCrawl();

            // Calculate summary
            const failedPages = this.pageResults.filter(r => !r.contentValid || r.error).length;
            const suspiciousPages = this.pageResults.filter(r =>
                r.validation.hasErrorIndicator ||
                r.validation.hasStuckSpinner ||
                r.contentLength < this.linkConfig.minContentLength ||
                (r.visualResult && !r.visualResult.passed)
            ).length;

            const totalDuration = Date.now() - startTime;

            logger.info('');
            logger.info('═'.repeat(60));
            logger.info('CRAWL COMPLETE (Parallel Mode)');
            logger.info('═'.repeat(60));
            logger.info(`Pages visited: ${this.pageResults.length}`);
            logger.info(`Failed pages: ${failedPages}`);
            logger.info(`Suspicious pages: ${suspiciousPages}`);
            logger.info(`Console errors: ${this.allConsoleErrors.length}`);
            logger.info(`Duration: ${(totalDuration / 1000).toFixed(2)}s`);
            logger.info(`Concurrency used: ${concurrency}`);

            const result = {
                startUrl: baseUrl,
                pagesVisited: this.pageResults.length,
                pageResults: this.pageResults,
                highValueLinksFound: this.urlQueue.length + this.pageResults.length,
                failedPages,
                suspiciousPages,
                totalConsoleErrors: this.allConsoleErrors.length,
                totalDuration,
                timestamp: new Date().toISOString(),
                concurrency,
            };

            // Mark WAL session as complete
            if (this.persistence) {
                await this.persistence.complete(result);
            }

            return result;

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`Crawl failed: ${errMsg}`);
            throw error;
        }
    }

    /**
     * Atomic page counter for thread-safe parallel crawling
     */
    private pageCounter = { count: 1 };

    /**
     * Thread-safe increment of page counter
     * Returns the new count after increment
     */
    private incrementPageCount(): number {
        return ++this.pageCounter.count;
    }

    /**
     * Get current page count (thread-safe read)
     */
    private getPageCount(): number {
        return this.pageCounter.count;
    }

    /**
     * Process URLs in parallel using bounded concurrency
     */
    private async parallelCrawl(): Promise<void> {
        if (!this.limit) {
            throw new Error('Concurrency limiter not initialized');
        }

        // Reset page counter (homepage already visited = 1)
        this.pageCounter.count = 1;
        const maxPages = this.linkConfig.maxPages;

        // Process queue with dynamic addition
        while (this.urlQueue.length > 0 && this.getPageCount() < maxPages) {
            // Take a batch of URLs to process
            const batchSize = Math.min(
                this.urlQueue.length,
                maxPages - this.getPageCount(),
                this.linkConfig.concurrency * 2 // Process 2x concurrency at a time
            );

            const batch = this.urlQueue.splice(0, batchSize);
            const urlsToProcess: string[] = [];

            // Filter already visited URLs
            for (const url of batch) {
                const normalized = this.normalizeUrl(url);
                if (!this.visitedUrls.has(normalized)) {
                    this.visitedUrls.add(normalized);
                    urlsToProcess.push(url);
                }
            }

            if (urlsToProcess.length === 0) continue;

            logger.info(`Processing batch of ${urlsToProcess.length} URLs (${this.getPageCount()}/${maxPages} total)`);

            // Create parallel tasks with concurrency limit
            const tasks = urlsToProcess.map(url =>
                this.limit!(async () => {
                    // Atomically increment and capture current page number
                    const currentPage = this.incrementPageCount();

                    try {
                        logger.info(`  [${currentPage}/${maxPages}] Crawling: ${url}`);
                        const result = await this.visitPageParallel(url);

                        // Thread-safe addition to results
                        this.pageResults.push(result);
                        this.logPageResult(result);

                        // Log result to WAL immediately
                        if (this.persistence) {
                            await this.persistence.log('page_result', result);
                        }

                        // Discover new links from this page
                        if (result.linksFound > 0 && this.getPageCount() < maxPages) {
                            // Links are already added to queue during visitPageParallel
                        }

                        return result;
                    } catch (error) {
                        const errMsg = error instanceof Error ? error.message : String(error);
                        logger.error(`  [${currentPage}/${maxPages}] Failed: ${url} - ${errMsg}`);

                        // Return error result instead of throwing
                        const errorResult: PageCrawlResult = {
                            url,
                            status: null,
                            title: '',
                            contentValid: false,
                            contentLength: 0,
                            linksFound: 0,
                            duration: 0,
                            error: errMsg,
                            validation: {
                                valid: false,
                                length: 0,
                                hasErrorIndicator: false,
                                hasStuckSpinner: false,
                                consoleErrors: [],
                            },
                        };
                        this.pageResults.push(errorResult);

                        // Log error result to WAL
                        if (this.persistence) {
                            await this.persistence.log('page_result', errorResult);
                        }

                        return errorResult;
                    }
                })
            );

            // Wait for all tasks in this batch to complete
            await Promise.allSettled(tasks);
        }
    }

    /**
     * Visit a page using an isolated page tab (for parallel execution)
     */
    private async visitPageParallel(url: string): Promise<PageCrawlResult> {
        const startTime = Date.now();
        let page: Page | null = null;

        try {
            // Create a new isolated page for this URL
            page = await this.browserService.createNewPage();

            // Human-like delay before navigation
            await this.humanDelay();

            // Navigate to the URL
            const response = await page.goto(url, {
                waitUntil: 'domcontentloaded',
                timeout: 60000,
            });

            const status = response?.status() ?? null;
            const title = await page.title();

            // Validate content on this page
            const validation = await this.validateContentOnPage(page, url);

            // Collect console errors (from this page's context)
            // Note: Console errors are captured by the page-level listeners attached via ScannerRegistry

            // Asset validation
            const assetResult = await this.assetValidator.check(page);

            // SEO validation
            const seoResult = await this.seoValidator.check(page, url);

            // Discover and queue new links
            const links = await this.discoverLinksFromPage(page);
            const highValueLinks = this.filterHighValueLinks(links);
            const internalLinks = this.filterInternalLinks(links);

            // Check for broken links
            const linkCheckResult = await this.linkChecker.checkLinks(internalLinks, url);

            // Queue new high-value links (thread-safe)
            let newLinksAdded = 0;
            for (const link of highValueLinks) {
                const normalized = this.normalizeUrl(link);
                if (!this.visitedUrls.has(normalized) && !this.urlQueue.includes(link)) {
                    this.urlQueue.push(link);
                    newLinksAdded++;
                }
            }

            // Mark invalid if assets or links are broken or SEO failed
            if ((assetResult && assetResult.brokenImages.length > 0) ||
                (linkCheckResult.brokenLinks.length > 0) ||
                (seoResult && !seoResult.valid)) {
                validation.valid = false;
            }

            return {
                url,
                status,
                title,
                contentValid: validation.valid,
                contentLength: validation.length,
                linksFound: highValueLinks.length,
                duration: Date.now() - startTime,
                validation,
                assetResult,
                linkCheckResult,
                seoResult,
            };

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);

            return {
                url,
                status: null,
                title: '',
                contentValid: false,
                contentLength: 0,
                linksFound: 0,
                duration: Date.now() - startTime,
                error: errMsg,
                validation: {
                    valid: false,
                    length: 0,
                    hasErrorIndicator: false,
                    hasStuckSpinner: false,
                    consoleErrors: [],
                },
            };
        } finally {
            // Always close the page to free resources
            if (page) {
                await this.browserService.closePage(page);
            }
        }
    }

    /**
     * Visit a page using the main browser page (for initial homepage visit)
     */
    private async visitPage(url: string, isHomepage = false): Promise<PageCrawlResult> {
        const startTime = Date.now();
        const normalizedUrl = this.normalizeUrl(url);

        this.visitedUrls.add(normalizedUrl);

        // Clear console errors before navigation
        this.browserService.clearConsoleErrors();

        try {
            // Navigate with human delay
            const navResult = await this.browserService.goto(url);
            const title = await this.browserService.getTitle();

            // Full content validation
            const validation = await this.validateContent(url);

            // Collect console errors
            const pageConsoleErrors = this.browserService.getConsoleErrors();
            this.allConsoleErrors.push(...pageConsoleErrors);
            validation.consoleErrors = pageConsoleErrors;

            // Visual Regression Check (Only if content is valid and it's the homepage)
            let visualResult: VisualTestResult | undefined;
            if (validation.valid && isHomepage && this.linkConfig.enableVisualRegression) {
                try {
                    const pageName = this.getPageName(url);
                    const screenshot = await this.browserService.screenshot(`visual_temp_${pageName}`);
                    visualResult = await this.visualSentinel.checkVisual(pageName, screenshot.path);
                } catch (vError) {
                    logger.warn(`Visual check failed: ${vError}`);
                }
            }

            // Asset, SEO validation
            let assetResult: AssetCheckResult | undefined;
            let seoResult: SEOResult | undefined;
            let interactionResult: InteractionTestResult | undefined;
            let resilienceResult: ResilienceCheckResult | undefined;
            let a11yResult: A11yResult | undefined;

            const page = this.browserService.getPage();
            if (page) {
                assetResult = await this.assetValidator.check(page);
                seoResult = await this.seoValidator.check(page, url);

                // Accessibility Scan (Run on homepage)
                if (this.a11yTestsRun === 0 && isHomepage) {
                    a11yResult = await this.a11yScanner.scan(page, url);
                    this.a11yTestsRun++;
                }
            }

            // Discover links
            const links = await this.discoverLinks();
            const highValueLinks = this.filterHighValueLinks(links);
            const internalLinks = this.filterInternalLinks(links);
            const linkCheckResult = await this.linkChecker.checkLinks(internalLinks, url);

            // Flag as suspicious if assets are broken, links are broken, or SEO failed
            if ((assetResult && assetResult.brokenImages.length > 0) ||
                (linkCheckResult.brokenLinks.length > 0) ||
                (seoResult && !seoResult.valid)) {
                validation.valid = false;
            }

            return {
                url,
                status: navResult.status,
                title,
                contentValid: validation.valid,
                contentLength: validation.length,
                linksFound: highValueLinks.length,
                duration: Date.now() - startTime,
                validation,
                visualResult,
                assetResult,
                linkCheckResult,
                seoResult,
                interactionResult,
                resilienceResult,
                a11yResult
            };

        } catch (error: unknown) {
            const errMsg = error instanceof Error ? error.message : String(error);

            // Take error screenshot
            let screenshotPath: string | undefined;
            try {
                const result = await this.browserService.screenshot(`error-${this.getPageName(url)}`);
                screenshotPath = result.path;
            } catch { /* ignore */ }

            return {
                url,
                status: null,
                title: '',
                contentValid: false,
                contentLength: 0,
                linksFound: 0,
                duration: Date.now() - startTime,
                error: errMsg,
                validation: {
                    valid: false,
                    length: 0,
                    hasErrorIndicator: false,
                    hasStuckSpinner: false,
                    consoleErrors: this.browserService.getConsoleErrors(),
                    screenshotPath,
                },
            };
        }
    }

    /**
     * Validate content on a specific page instance
     */
    private async validateContentOnPage(page: Page, url: string): Promise<ContentValidation> {
        const validation: ContentValidation = {
            valid: true,
            length: 0,
            hasErrorIndicator: false,
            hasStuckSpinner: false,
            consoleErrors: [],
        };

        try {
            // Check for stuck loading spinners
            for (const selector of this.linkConfig.spinnerSelectors) {
                const spinner = await page.$(selector);
                if (spinner) {
                    const startWait = Date.now();
                    while (Date.now() - startWait < this.linkConfig.spinnerTimeout) {
                        await new Promise(r => setTimeout(r, 500));
                        const stillExists = await page.$(selector);
                        if (!stillExists) break;
                    }
                    const stillThere = await page.$(selector);
                    if (stillThere) {
                        validation.hasStuckSpinner = true;
                        validation.valid = false;
                        break;
                    }
                }
            }

            // Get body text and check length
            const bodyText = await page.textContent('body') || '';
            validation.length = bodyText.length;

            // Check for error indicators
            const errorFound = this.checkForErrorIndicators(bodyText);
            if (errorFound) {
                validation.hasErrorIndicator = true;
                validation.errorIndicatorFound = errorFound;
                validation.valid = false;
            }

            // Check content length
            if (validation.length < this.linkConfig.minContentLength) {
                validation.valid = false;
            }

        } catch (error) {
            validation.valid = false;
        }

        return validation;
    }

    /**
     * Full content validation with error detection (using main browser page)
     */
    private async validateContent(url: string): Promise<ContentValidation> {
        const validation: ContentValidation = {
            valid: true,
            length: 0,
            hasErrorIndicator: false,
            hasStuckSpinner: false,
            consoleErrors: [],
        };

        // Step 1: Check for stuck loading spinners
        validation.hasStuckSpinner = await this.checkForStuckSpinner();
        if (validation.hasStuckSpinner) {
            logger.warn(`  ⚠ Loading spinner still visible after ${this.linkConfig.spinnerTimeout}ms`);
            validation.valid = false;
            validation.screenshotPath = await this.takeScreenshot(`suspect-spinner-${this.getPageName(url)}`);
        }

        // Step 2: Get body text and check length
        const bodyText = await this.browserService.getText('body') || '';
        validation.length = bodyText.length;

        // Step 3: Check for error indicators in page content
        const errorFound = this.checkForErrorIndicators(bodyText);
        if (errorFound) {
            validation.hasErrorIndicator = true;
            validation.errorIndicatorFound = errorFound;
            validation.valid = false;
            logger.warn(`  ⚠ Error indicator found: "${errorFound}"`);

            if (!validation.screenshotPath) {
                validation.screenshotPath = await this.takeScreenshot(`suspect-error-${this.getPageName(url)}`);
            }
        }

        // Step 4: Check content length
        if (validation.length < this.linkConfig.minContentLength) {
            validation.valid = false;
            logger.warn(`  ⚠ Content suspiciously short: ${validation.length} chars (min: ${this.linkConfig.minContentLength})`);

            if (!validation.screenshotPath) {
                validation.screenshotPath = await this.takeScreenshot(`suspect-short-${this.getPageName(url)}`);
            }
        }

        // Step 5: Try to find main content container
        if (validation.valid) {
            let foundContainer = false;
            for (const selector of this.linkConfig.contentSelectors) {
                const exists = await this.browserService.elementExists(selector);
                if (exists) {
                    const text = await this.browserService.getText(selector);
                    if (text && text.length >= this.linkConfig.minContentLength) {
                        foundContainer = true;
                        validation.length = text.length;
                        break;
                    }
                }
            }

            if (!foundContainer && validation.length < this.linkConfig.minContentLength) {
                validation.valid = false;
            }
        }

        return validation;
    }

    /**
     * Check if a loading spinner is stuck on the page
     */
    private async checkForStuckSpinner(): Promise<boolean> {
        for (const selector of this.linkConfig.spinnerSelectors) {
            const exists = await this.browserService.elementExists(selector);
            if (exists) {
                // Wait for spinner to disappear
                const startWait = Date.now();
                while (Date.now() - startWait < this.linkConfig.spinnerTimeout) {
                    await new Promise(r => setTimeout(r, 500));
                    const stillExists = await this.browserService.elementExists(selector);
                    if (!stillExists) {
                        return false; // Spinner disappeared
                    }
                }
                // Spinner still visible after timeout
                return true;
            }
        }
        return false;
    }

    /**
     * Check for error indicators in page content
     */
    private checkForErrorIndicators(bodyText: string): string | null {
        const lowerText = bodyText.toLowerCase();

        for (const indicator of this.linkConfig.errorIndicators) {
            if (lowerText.includes(indicator.toLowerCase())) {
                return indicator;
            }
        }

        return null;
    }

    /**
     * Take a screenshot and return the path
     */
    private async takeScreenshot(name: string): Promise<string | undefined> {
        try {
            const result = await this.browserService.screenshot(name);
            logger.info(`  📸 Screenshot saved: ${result.path}`);
            return result.path;
        } catch (error) {
            logger.debug(`Failed to take screenshot: ${error}`);
            return undefined;
        }
    }

    /**
     * Extract page name from URL for screenshot naming
     */
    private getPageName(url: string): string {
        try {
            const parsed = new URL(url);
            const path = parsed.pathname.replace(/\//g, '-').replace(/^-|-$/g, '');
            return path || 'home';
        } catch {
            return 'unknown';
        }
    }

    /**
     * Log page result with appropriate styling
     */
    private logPageResult(result: PageCrawlResult): void {
        if (result.error) {
            logger.error(`    ✗ Error: ${result.error}`);
        } else if (!result.contentValid) {
            logger.warn(`    ⚠ Invalid content:`);
            if (result.validation.hasErrorIndicator) {
                logger.warn(`      - Error indicator: "${result.validation.errorIndicatorFound}"`);
            }
            if (result.validation.hasStuckSpinner) {
                logger.warn(`      - Loading spinner stuck`);
            }
            if (result.contentLength < this.linkConfig.minContentLength) {
                logger.warn(`      - Content too short (${result.contentLength} chars)`);
            }
        } else {
            let msg = `    ✓ Valid (${result.contentLength} chars, ${result.linksFound} links)`;
            if (result.visualResult) {
                msg += result.visualResult.passed ? ' [Visual: OK]' : ' [Visual: FAIL]';
            }
            logger.info(msg);
        }
    }

    /**
     * Discover all links on the current page (using main page)
     */
    private async discoverLinks(): Promise<string[]> {
        try {
            return await this.browserService.getAllLinks();
        } catch (error) {
            logger.debug(`Link discovery error: ${error}`);
            return [];
        }
    }

    /**
     * Discover links from a specific page instance
     */
    private async discoverLinksFromPage(page: Page): Promise<string[]> {
        try {
            const links = await page.evaluate(() => {
                const anchors = document.querySelectorAll('a[href]');
                return Array.from(anchors)
                    .map(a => (a as HTMLAnchorElement).href)
                    .filter(href => href && href.startsWith('http'));
            });
            return links;
        } catch (error) {
            logger.debug(`Link discovery error: ${error}`);
            return [];
        }
    }

    /**
     * Filter links to only those on the same domain
     */
    private filterInternalLinks(links: string[]): string[] {
        const baseHost = new URL(this.config.LIVE_URL).host;
        return links.filter(link => {
            try {
                const url = new URL(link, this.config.LIVE_URL);
                return url.host === baseHost;
            } catch {
                return false;
            }
        });
    }

    /**
     * Filter links to only high-value pages
     */
    private filterHighValueLinks(links: string[]): string[] {
        const baseHost = new URL(this.config.LIVE_URL).host;

        return links.filter(link => {
            try {
                const url = new URL(link, this.config.LIVE_URL);

                if (url.host !== baseHost) return false;

                const path = url.pathname.toLowerCase();

                for (const ignorePath of this.linkConfig.ignorePaths) {
                    if (path.includes(ignorePath.toLowerCase()) || link.includes(ignorePath)) {
                        return false;
                    }
                }

                for (const keyword of this.linkConfig.priorityKeywords) {
                    if (path.includes(keyword.toLowerCase())) {
                        return true;
                    }
                }

                return false;
            } catch {
                return false;
            }
        });
    }

    /**
     * Normalize URL for comparison
     */
    private normalizeUrl(url: string): string {
        try {
            const parsed = new URL(url, this.config.LIVE_URL);
            return `${parsed.origin}${parsed.pathname.replace(/\/$/, '')}`.toLowerCase();
        } catch {
            return url.toLowerCase();
        }
    }

    /**
     * Get all console errors collected during crawl
     */
    getConsoleErrors(): ConsoleError[] {
        return [...this.allConsoleErrors];
    }

    /**
     * Get list of visited URLs
     */
    getVisitedUrls(): string[] {
        return Array.from(this.visitedUrls);
    }

    /**
     * Get remaining queue
     */
    getQueue(): string[] {
        return [...this.urlQueue];
    }

    /**
     * Get the Write-Ahead Log file path
     * Useful for generating reports from WAL data
     */
    getWalFilePath(): string | null {
        return this.persistence?.getLogFilePath() ?? null;
    }
}

export default CrawlerService;
