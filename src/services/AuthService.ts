/**
 * AuthService
 * 
 * Handles authentication flows for the Live Site Compliance Monitor.
 * Uses BrowserService for all interactions, ensuring human-like behavior.
 */

import { BrowserService } from './BrowserService';
import { getConfig, EnvConfig } from '../config/env';
import { createConfig } from '../config/compliance.config';
import { logger } from '../utils/logger';

/**
 * Login selectors configuration
 * Can be customized per-site
 */
export interface LoginSelectors {
    /** Selector for email/username input */
    emailInput: string;
    /** Selector for password input */
    passwordInput: string;
    /** Selector for submit button */
    submitButton: string;
    /** Selector that indicates successful login */
    successIndicator: string;
}

/**
 * Default login selectors - covers common patterns
 */
const DEFAULT_SELECTORS: LoginSelectors = {
    emailInput: 'input[type="email"], input[name="email"], input[name="username"], #email, #username',
    passwordInput: 'input[type="password"], input[name="password"], #password',
    submitButton: 'button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in"), .login-btn, #login-btn',
    successIndicator: 'a:has-text("Dashboard"), a:has-text("Profile"), button:has-text("Logout"), a:has-text("Logout"), .user-menu, [data-testid="dashboard"], .logout-btn',
};

/**
 * Authentication result
 */
export interface AuthResult {
    success: boolean;
    message: string;
    screenshotPath?: string;
    duration: number;
}

/**
 * AuthService Class
 * 
 * Manages login/logout flows with:
 * - Human-like typing delays
 * - Comprehensive error handling
 * - Screenshot capture on failure
 * - Step-by-step logging
 */
export class AuthService {
    private readonly browserService: BrowserService;
    private readonly config: EnvConfig;
    private readonly selectors: LoginSelectors;
    private isAuthenticated: boolean = false;

    /** Timeout for waiting for success indicator (ms) */
    private static readonly AUTH_TIMEOUT = 30000;

    /** Delay between keystrokes when typing (ms) */
    private static readonly KEYSTROKE_DELAY = 75;

    constructor(browserService: BrowserService, selectors?: Partial<LoginSelectors>) {
        this.browserService = browserService;
        this.config = getConfig();
        this.selectors = { ...DEFAULT_SELECTORS, ...selectors };
    }

    /**
     * Perform login flow
     * @returns AuthResult with success status and details
     */
    /**
     * Perform login flow
     * @returns AuthResult with success status and details
     */
    async login(overrideTargetUrl?: string): Promise<AuthResult> {
        const startTime = Date.now();
        logger.info('Starting authentication flow...');

        try {
            // Step 0: Check for Direct Token Injection
            if (await this.injectSession(overrideTargetUrl)) {
                logger.info('Direct Token Injection successful for SSO/Context Bypass');
                this.isAuthenticated = true;
                const duration = Date.now() - startTime;
                return {
                    success: true,
                    message: 'Authentication successful (Token Injection)',
                    duration
                };
            }

            // Step 1: Navigate to login page
            logger.info('Step 1/5: Navigating to login page...');

            // Determine base URL
            let baseUrl = this.config.LIVE_URL;
            if (overrideTargetUrl) {
                baseUrl = overrideTargetUrl;
            } else if (Array.isArray(this.config.LIVE_URL) && this.config.LIVE_URL.length > 0) {
                // Fallback if not overridden and LIVE_URL is actually an array (unlikely for strict EnvConfig but good for safety)
                // Actually EnvConfig LIVE_URL is string. But createConfig's targetUrl can be array.
                // This.config is EnvConfig, so it is string.
                baseUrl = this.config.LIVE_URL;
            }

            // Ensure we don't double slash if base ends with /
            const loginUrl = baseUrl.endsWith('/') ? `${baseUrl}login` : `${baseUrl}/login`;
            const navResult = await this.browserService.goto(loginUrl);

            if (!navResult.ok && navResult.status !== null) {
                throw new Error(`Login page returned status ${navResult.status}`);
            }
            logger.info(`Navigated to: ${loginUrl} (${navResult.status})`);

            // Step 2: Wait for email input
            logger.info('Step 2/5: Waiting for email input field...');
            const emailFound = await this.browserService.waitForSelector(
                this.selectors.emailInput,
                10000
            );

            if (!emailFound) {
                throw new Error(`Email input not found: ${this.selectors.emailInput}`);
            }
            logger.info('Email input field found');

            // Step 3: Type email (with keystroke delay for human-like behavior)
            logger.info('Step 3/5: Entering email...');
            const emailResult = await this.browserService.type(
                this.selectors.emailInput,
                this.config.TEST_EMAIL
            );

            if (!emailResult.success) {
                throw new Error(`Failed to type email: ${emailResult.error}`);
            }
            logger.info(`Email entered: ${this.maskEmail(this.config.TEST_EMAIL)}`);

            // Step 4: Type password
            logger.info('Step 4/5: Entering password...');
            const passwordResult = await this.browserService.type(
                this.selectors.passwordInput,
                this.config.TEST_PASSWORD
            );

            if (!passwordResult.success) {
                throw new Error(`Failed to type password: ${passwordResult.error}`);
            }
            logger.info('Password entered: ********');

            // Step 5: Click submit button
            logger.info('Step 5/5: Clicking submit button...');
            const submitResult = await this.browserService.click(this.selectors.submitButton);

            if (!submitResult.success) {
                throw new Error(`Failed to click submit: ${submitResult.error}`);
            }
            logger.info('Submit button clicked');

            // Verification: Wait for success indicator
            logger.info(`Waiting for success indicator (timeout: ${AuthService.AUTH_TIMEOUT}ms)...`);
            const successFound = await this.browserService.waitForSelector(
                this.selectors.successIndicator,
                AuthService.AUTH_TIMEOUT
            );

            if (!successFound) {
                // Authentication failed - take screenshot
                logger.error('Success indicator not found within timeout');
                const screenshot = await this.captureFailureScreenshot('auth_fail');

                throw new AuthenticationError(
                    'Login verification failed: Success indicator not found within 30 seconds',
                    screenshot
                );
            }

            // Success!
            this.isAuthenticated = true;
            const duration = Date.now() - startTime;

            logger.info(`Authentication successful! Duration: ${duration}ms`);
            logger.info(`Current URL: ${this.browserService.getCurrentUrl()}`);

            return {
                success: true,
                message: 'Authentication successful',
                duration,
            };

        } catch (error) {
            const duration = Date.now() - startTime;
            const errorMessage = error instanceof Error ? error.message : String(error);

            logger.error(`Authentication failed: ${errorMessage}`);

            // Capture screenshot if not already captured
            let screenshotPath: string | undefined;
            if (error instanceof AuthenticationError) {
                screenshotPath = error.screenshotPath;
            } else {
                screenshotPath = await this.captureFailureScreenshot('auth_error');
            }

            return {
                success: false,
                message: errorMessage,
                screenshotPath,
                duration,
            };
        }
    }

    /**
     * Inject session token directly to bypass login forms (SSO/MFA)
     */
    async injectSession(overrideTargetUrl?: string): Promise<boolean> {
        const runtimeConfig = createConfig();

        if (!runtimeConfig.authBypass) {
            return false;
        }

        logger.info(`Attempting Direct Token Injection for ${runtimeConfig.authBypass.domain}...`);

        try {
            await this.browserService.addCookies([{
                name: runtimeConfig.authBypass.cookieName,
                value: runtimeConfig.authBypass.tokenValue,
                domain: runtimeConfig.authBypass.domain,
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'Lax'
            }]);

            // Determine target URL
            let target = overrideTargetUrl;
            if (!target) {
                target = Array.isArray(runtimeConfig.targetUrl)
                    ? runtimeConfig.targetUrl[0]
                    : runtimeConfig.targetUrl;
            }

            // Navigate to root to verify session
            await this.browserService.goto(target);

            // Verify success indicator
            const isLoggedIn = await this.browserService.elementExists(this.selectors.successIndicator);

            if (isLoggedIn) {
                logger.info('Token injection verified: User is logged in.');
                return true;
            } else {
                logger.warn('Token injection failed: Success indicator not found after injection.');
                return false;
            }

        } catch (error) {
            logger.error(`Direct Token Injection error: ${error}`);
            return false;
        }
    }

    /**
     * Check if currently authenticated
     */
    async isLoggedIn(): Promise<boolean> {
        if (!this.isAuthenticated) {
            return false;
        }

        // Verify by checking for success indicator
        return await this.browserService.elementExists(this.selectors.successIndicator);
    }

    /**
     * Perform logout if logout button is available
     */
    async logout(): Promise<boolean> {
        logger.info('Attempting logout...');

        try {
            // Common logout selectors
            const logoutSelectors = [
                'button:has-text("Logout")',
                'a:has-text("Logout")',
                'button:has-text("Sign out")',
                'a:has-text("Sign out")',
                '.logout-btn',
                '#logout-btn',
                '[data-testid="logout"]',
            ];

            for (const selector of logoutSelectors) {
                const exists = await this.browserService.elementExists(selector);
                if (exists) {
                    await this.browserService.click(selector);
                    this.isAuthenticated = false;
                    logger.info('Logout successful');
                    return true;
                }
            }

            logger.warn('No logout button found');
            return false;
        } catch (error) {
            logger.error(`Logout failed: ${error}`);
            return false;
        }
    }

    /**
     * Capture failure screenshot
     */
    private async captureFailureScreenshot(name: string): Promise<string | undefined> {
        try {
            const result = await this.browserService.screenshot(name);
            logger.info(`Failure screenshot saved: ${result.path}`);
            return result.path;
        } catch (e) {
            logger.warn('Failed to capture failure screenshot');
            return undefined;
        }
    }

    /**
     * Mask email for logging (privacy)
     */
    private maskEmail(email: string): string {
        const [local, domain] = email.split('@');
        if (!domain) return '***@***';

        const maskedLocal = local.length > 2
            ? `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`
            : '***';

        return `${maskedLocal}@${domain}`;
    }

    /**
     * Get current authentication status
     */
    getAuthStatus(): { isAuthenticated: boolean } {
        return { isAuthenticated: this.isAuthenticated };
    }
}

/**
 * Custom error for authentication failures
 */
export class AuthenticationError extends Error {
    public readonly screenshotPath?: string;

    constructor(message: string, screenshotPath?: string) {
        super(message);
        this.name = 'AuthenticationError';
        this.screenshotPath = screenshotPath;
    }
}

export default AuthService;
