/**
 * SecurityAssessment Service
 *
 * Performs safe, non-destructive black-box security testing on live sites.
 *
 * SAFETY GUARANTEES:
 * - All tests are READ-ONLY or use safe detection payloads
 * - No data modification attempts
 * - No brute force attacks
 * - No denial of service vectors
 * - Rate-limited to prevent triggering WAF
 *
 * Tests Performed:
 * 1. IDOR (Insecure Direct Object Reference) detection
 * 2. XSS reflection detection (safe payloads)
 * 3. SQL injection detection (safe payloads)
 * 4. Rate limiting verification
 * 5. Authentication bypass checks
 * 6. Information disclosure detection
 */

import { Page } from 'playwright';
import { logger } from '../utils/logger.js';
import { randomInt } from '../utils/random.js';
import { baselineService } from './BaselineService.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface SecurityFinding {
    id: string;
    category: 'idor' | 'xss' | 'sqli' | 'auth' | 'rate-limit' | 'info-disclosure' | 'csrf';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    title: string;
    description: string;
    evidence: string;
    endpoint: string;
    remediation: string;
    cweId?: string;
    owaspCategory?: string;
}

export interface SecurityAssessmentResult {
    target: string;
    timestamp: string;
    duration: number;
    findings: SecurityFinding[];
    ignored_findings: SecurityFinding[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        totalTests: number;
    };
    reconnaissance: ReconData;
}

export interface ReconData {
    endpoints: EndpointInfo[];
    parameters: ParameterInfo[];
    authMechanism: string;
    techStack: string[];
    cookies: CookieInfo[];
}

interface EndpointInfo {
    url: string;
    method: string;
    type: 'page' | 'api' | 'static' | 'auth';
    parameters?: string[];
    requiresAuth: boolean;
}

interface ParameterInfo {
    name: string;
    location: 'url' | 'body' | 'header' | 'cookie';
    endpoint: string;
    type: 'id' | 'search' | 'filter' | 'auth' | 'other';
}

interface CookieInfo {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE TEST PAYLOADS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * XSS Detection Payloads - SAFE
 * These payloads are designed to be detected in responses WITHOUT executing
 * They use unlikely strings that wouldn't appear naturally
 */
const XSS_DETECTION_PAYLOADS = [
    // Simple reflection test (no execution)
    { payload: '<scm-xss-test>', description: 'Basic HTML tag reflection' },
    // Attribute breakout detection
    { payload: '"><scm-xss-attr>', description: 'Attribute context breakout' },
    // JavaScript context detection
    { payload: "'-scm-xss-js-'", description: 'JavaScript string breakout' },
    // Template literal detection (Next.js/React)
    { payload: '${scm-xss-template}', description: 'Template literal injection' },
    // Event handler detection
    { payload: '" onmouseover="scm-xss', description: 'Event handler injection' },
];

/**
 * SQL Injection Detection Payloads - SAFE
 * These cause detectable errors WITHOUT modifying data
 * Designed for PostgreSQL (Supabase backend)
 */
const SQLI_DETECTION_PAYLOADS = [
    // Syntax error triggers (read-only detection)
    { payload: "' OR '1'='1", description: 'Classic OR injection', errorPattern: /syntax|error|pg_|postgresql/i },
    { payload: "1' AND '1'='2", description: 'Boolean-based blind (false)', errorPattern: /syntax|error/i },
    { payload: "1; SELECT 1--", description: 'Stacked query attempt', errorPattern: /syntax|error|pg_/i },
    // Time-based detection (safe - just delays response)
    { payload: "1' AND pg_sleep(1)--", description: 'Time-based blind (1 sec)', timeBased: true },
    // PostgreSQL specific
    { payload: "' UNION SELECT NULL--", description: 'UNION injection probe', errorPattern: /column|type|union/i },
];

/**
 * IDOR Test Patterns
 * Tests for unauthorized access to resources by manipulating IDs
 */
const IDOR_PATTERNS = [
    { original: '{id}', test: '1', description: 'Sequential ID test' },
    { original: '{id}', test: '0', description: 'Zero ID boundary' },
    { original: '{id}', test: '-1', description: 'Negative ID boundary' },
    { original: '{id}', test: '999999999', description: 'Large ID boundary' },
    { original: '{uuid}', test: '00000000-0000-0000-0000-000000000000', description: 'Null UUID test' },
];

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class SecurityAssessment {
    private findings: SecurityFinding[] = [];
    private recon: ReconData = {
        endpoints: [],
        parameters: [],
        authMechanism: 'unknown',
        techStack: [],
        cookies: []
    };
    private testCount = 0;

    /**
     * Run full security assessment
     */
    async assess(page: Page, targetUrl: string, discoveredUrls: string[]): Promise<SecurityAssessmentResult> {
        const startTime = Date.now();
        this.findings = [];
        this.testCount = 0;

        logger.info('═'.repeat(50));
        logger.info('SECURITY ASSESSMENT - Starting');
        logger.info('═'.repeat(50));
        logger.info(`Target: ${targetUrl}`);
        logger.info('Mode: Safe/Non-Destructive');
        logger.info('');

        try {
            // Phase 1: Reconnaissance
            logger.info('Phase 1: Reconnaissance...');
            await this.performReconnaissance(page, targetUrl, discoveredUrls);

            // Phase 2: IDOR Testing
            logger.info('Phase 2: IDOR Testing...');
            await this.testIDOR(page);

            // Phase 3: XSS Detection
            logger.info('Phase 3: XSS Detection...');
            await this.testXSS(page);

            // Phase 4: SQL Injection Detection
            logger.info('Phase 4: SQLi Detection...');
            await this.testSQLi(page);

            // Phase 5: Rate Limiting Check
            logger.info('Phase 5: Rate Limiting Check...');
            await this.testRateLimiting(page);

            // Phase 6: Authentication Checks
            logger.info('Phase 6: Authentication Checks...');
            await this.testAuthenticationBypass(page);

            // Phase 7: Information Disclosure
            logger.info('Phase 7: Information Disclosure...');
            await this.testInformationDisclosure(page);

        } catch (error) {
            logger.error(`Assessment error: ${error instanceof Error ? error.message : String(error)}`);
        }

        const duration = Date.now() - startTime;

        // Filter findings against baseline
        const finalFindings: SecurityFinding[] = [];
        const ignoredFindings: SecurityFinding[] = [];

        for (const finding of this.findings) {
            // Check against baseline (ID/Category, no selector, Endpoint as path)
            if (baselineService.shouldIgnore(finding.id, undefined, finding.endpoint) ||
                baselineService.shouldIgnore(finding.category, undefined, finding.endpoint)) {
                ignoredFindings.push(finding);
                logger.debug(`Ignored finding: ${finding.id} (${finding.category})`);
            } else {
                finalFindings.push(finding);
            }
        }

        // Generate summary
        const summary = {
            critical: finalFindings.filter(f => f.severity === 'CRITICAL').length,
            high: finalFindings.filter(f => f.severity === 'HIGH').length,
            medium: finalFindings.filter(f => f.severity === 'MEDIUM').length,
            low: finalFindings.filter(f => f.severity === 'LOW').length,
            info: finalFindings.filter(f => f.severity === 'INFO').length,
            totalTests: this.testCount
        };

        logger.info('');
        logger.info('═'.repeat(50));
        logger.info('ASSESSMENT COMPLETE');
        logger.info('═'.repeat(50));
        logger.info(`Tests Run: ${this.testCount}`);
        logger.info(`Findings: ${this.findings.length}`);
        logger.info(`  Critical: ${summary.critical}`);
        logger.info(`  High: ${summary.high}`);
        logger.info(`  Medium: ${summary.medium}`);
        logger.info(`  Low: ${summary.low}`);
        logger.info(`Duration: ${(duration / 1000).toFixed(2)}s`);

        return {
            target: targetUrl,
            timestamp: new Date().toISOString(),
            duration,
            findings: finalFindings,
            ignored_findings: ignoredFindings,
            summary,
            reconnaissance: this.recon
        };
    }

    /**
     * Phase 1: Reconnaissance - Identify attack surface
     */
    private async performReconnaissance(page: Page, targetUrl: string, discoveredUrls: string[]): Promise<void> {
        // Analyze discovered URLs
        for (const url of discoveredUrls) {
            const endpoint = this.analyzeEndpoint(url, targetUrl);
            if (endpoint) {
                this.recon.endpoints.push(endpoint);
            }
        }

        // Detect tech stack from page
        try {
            const techStack = await page.evaluate(() => {
                const detected: string[] = [];

                // Check for Next.js
                if (document.querySelector('script[src*="_next"]') ||
                    (window as any).__NEXT_DATA__) {
                    detected.push('Next.js');
                }

                // Check for React
                if ((window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
                    document.querySelector('[data-reactroot]')) {
                    detected.push('React');
                }

                // Check for Supabase
                if (document.querySelector('script[src*="supabase"]') ||
                    document.cookie.includes('sb-')) {
                    detected.push('Supabase');
                }

                // Check for Tailwind
                if (document.querySelector('[class*="flex"]') &&
                    document.querySelector('[class*="bg-"]')) {
                    detected.push('Tailwind CSS');
                }

                return detected;
            });
            this.recon.techStack = techStack;
        } catch (e) {
            logger.debug(`Tech stack detection failed: ${e}`);
        }

        // Analyze cookies
        try {
            const cookies = await page.context().cookies();
            this.recon.cookies = cookies.map(c => ({
                name: c.name,
                secure: c.secure,
                httpOnly: c.httpOnly,
                sameSite: c.sameSite || 'None'
            }));

            // Check for auth mechanism
            if (cookies.some(c => c.name.includes('sb-') || c.name.includes('supabase'))) {
                this.recon.authMechanism = 'Supabase Auth (JWT)';
            } else if (cookies.some(c => c.name.includes('session') || c.name.includes('auth'))) {
                this.recon.authMechanism = 'Session-based';
            }
        } catch (e) {
            logger.debug(`Cookie analysis failed: ${e}`);
        }

        // Extract parameters from URLs
        for (const url of discoveredUrls) {
            this.extractParameters(url);
        }

        logger.info(`  Found ${this.recon.endpoints.length} endpoints`);
        logger.info(`  Detected stack: ${this.recon.techStack.join(', ') || 'Unknown'}`);
        logger.info(`  Auth mechanism: ${this.recon.authMechanism}`);
    }

    /**
     * Phase 2: IDOR Testing
     */
    private async testIDOR(page: Page): Promise<void> {
        // Find endpoints with ID parameters
        const idorCandidates = this.recon.endpoints.filter(e =>
            e.url.includes('/profile/') ||
            e.url.includes('/user/') ||
            e.url.includes('/loadout/') ||
            e.url.match(/\/[a-f0-9-]{36}/) || // UUID pattern
            e.url.match(/\/\d+/) // Numeric ID pattern
        );

        for (const endpoint of idorCandidates.slice(0, 5)) { // Limit to 5 tests
            this.testCount++;

            try {
                // Test: Access another user's resource
                const testUrl = this.mutateUrlForIDOR(endpoint.url);
                if (!testUrl) continue;

                const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                const status = response?.status() || 0;

                // If we get a 200 on a resource that should be protected, flag it
                if (status === 200 && endpoint.requiresAuth) {
                    // Check if actual content is returned (not just a 200 redirect to login)
                    const content = await page.content();
                    if (!content.includes('login') && !content.includes('sign in') && content.length > 1000) {
                        this.findings.push({
                            id: `idor-${this.findings.length + 1}`,
                            category: 'idor',
                            severity: 'HIGH',
                            title: 'Potential IDOR Vulnerability',
                            description: `Endpoint may allow unauthorized access to other users' data by manipulating the ID parameter.`,
                            evidence: `Accessed ${testUrl} and received ${status} status with content`,
                            endpoint: endpoint.url,
                            remediation: 'Implement server-side authorization checks. Verify the authenticated user owns the requested resource before returning data.',
                            cweId: 'CWE-639',
                            owaspCategory: 'A01:2021 Broken Access Control'
                        });
                    }
                }

                await this.safeDelay();
            } catch (e) {
                logger.debug(`IDOR test failed for ${endpoint.url}: ${e}`);
            }
        }
    }

    /**
     * Phase 3: XSS Detection
     */
    private async testXSS(page: Page): Promise<void> {
        // Find endpoints with input potential
        const xssCandidates = [
            ...this.recon.parameters.filter(p => p.type === 'search' || p.type === 'filter'),
            // Also test URL path parameters
            ...this.recon.endpoints.filter(e => e.url.includes('/profile/') || e.url.includes('/search'))
        ];

        // Test search/filter parameters
        for (const param of xssCandidates.slice(0, 3)) {
            for (const xss of XSS_DETECTION_PAYLOADS.slice(0, 2)) { // Limit payloads
                this.testCount++;

                try {
                    const testUrl = this.injectPayload(
                        'endpoint' in param ? param.endpoint : (param as EndpointInfo).url,
                        'name' in param ? param.name : 'q',
                        xss.payload
                    );

                    const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                    const content = await page.content();

                    // Check if payload is reflected unencoded
                    if (content.includes(xss.payload)) {
                        this.findings.push({
                            id: `xss-${this.findings.length + 1}`,
                            category: 'xss',
                            severity: 'HIGH',
                            title: 'Reflected XSS Detected',
                            description: `User input is reflected in the page without proper encoding. ${xss.description}`,
                            evidence: `Payload "${xss.payload}" was reflected at ${testUrl}`,
                            endpoint: testUrl,
                            remediation: 'Implement output encoding using React/Next.js built-in escaping. Never use dangerouslySetInnerHTML with user input.',
                            cweId: 'CWE-79',
                            owaspCategory: 'A03:2021 Injection'
                        });
                        break; // One finding per endpoint is enough
                    }

                    await this.safeDelay();
                } catch (e) {
                    logger.debug(`XSS test failed: ${e}`);
                }
            }
        }

        // Test username/profile paths for XSS
        const profileEndpoint = this.recon.endpoints.find(e => e.url.includes('/profile/'));
        if (profileEndpoint) {
            for (const xss of XSS_DETECTION_PAYLOADS.slice(0, 2)) {
                this.testCount++;

                try {
                    // Test profile path with XSS payload
                    const baseUrl = new URL(profileEndpoint.url);
                    const testUrl = `${baseUrl.origin}/profile/${encodeURIComponent(xss.payload)}`;

                    const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                    const content = await page.content();

                    // Check if payload appears in the page (decoded)
                    if (content.includes(xss.payload)) {
                        this.findings.push({
                            id: `xss-path-${this.findings.length + 1}`,
                            category: 'xss',
                            severity: 'MEDIUM',
                            title: 'XSS via URL Path Parameter',
                            description: `URL path parameter is reflected without encoding. ${xss.description}`,
                            evidence: `Payload in path /profile/${xss.payload} was reflected`,
                            endpoint: testUrl,
                            remediation: 'Sanitize URL path parameters before rendering. Use Next.js dynamic routes with proper validation.',
                            cweId: 'CWE-79',
                            owaspCategory: 'A03:2021 Injection'
                        });
                        break;
                    }

                    await this.safeDelay();
                } catch (e) {
                    logger.debug(`Path XSS test failed: ${e}`);
                }
            }
        }
    }

    /**
     * Phase 4: SQL Injection Detection
     */
    private async testSQLi(page: Page): Promise<void> {
        // Find endpoints likely to have database interaction
        const sqliCandidates = this.recon.endpoints.filter(e =>
            e.url.includes('/profile/') ||
            e.url.includes('/search') ||
            e.url.includes('/filter') ||
            e.url.includes('/api/')
        );

        for (const endpoint of sqliCandidates.slice(0, 3)) {
            for (const sqli of SQLI_DETECTION_PAYLOADS.slice(0, 2)) {
                this.testCount++;

                try {
                    const testUrl = this.injectSQLiPayload(endpoint.url, sqli.payload);
                    const startTime = Date.now();

                    const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
                    const responseTime = Date.now() - startTime;
                    const content = await page.content();
                    const status = response?.status() || 0;

                    // Check for error-based detection
                    if (sqli.errorPattern && sqli.errorPattern.test(content)) {
                        this.findings.push({
                            id: `sqli-${this.findings.length + 1}`,
                            category: 'sqli',
                            severity: 'CRITICAL',
                            title: 'SQL Injection Detected (Error-Based)',
                            description: `Database error messages are exposed when injecting SQL syntax. ${sqli.description}`,
                            evidence: `Payload "${sqli.payload}" triggered database error at ${testUrl}`,
                            endpoint: endpoint.url,
                            remediation: 'Use parameterized queries (Supabase client handles this). Never concatenate user input into SQL strings. Disable verbose error messages in production.',
                            cweId: 'CWE-89',
                            owaspCategory: 'A03:2021 Injection'
                        });
                        break;
                    }

                    // Check for time-based detection
                    if (sqli.timeBased && responseTime > 1500) { // pg_sleep(1) + overhead
                        this.findings.push({
                            id: `sqli-time-${this.findings.length + 1}`,
                            category: 'sqli',
                            severity: 'CRITICAL',
                            title: 'SQL Injection Detected (Time-Based)',
                            description: `Server response was delayed, indicating time-based SQL injection. ${sqli.description}`,
                            evidence: `Payload "${sqli.payload}" caused ${responseTime}ms delay at ${testUrl}`,
                            endpoint: endpoint.url,
                            remediation: 'Use parameterized queries exclusively. Review all database queries for string concatenation.',
                            cweId: 'CWE-89',
                            owaspCategory: 'A03:2021 Injection'
                        });
                        break;
                    }

                    // Check for behavior change (boolean-based)
                    if (status === 500 || content.includes('error') || content.includes('Exception')) {
                        this.findings.push({
                            id: `sqli-behavior-${this.findings.length + 1}`,
                            category: 'sqli',
                            severity: 'HIGH',
                            title: 'Potential SQL Injection (Behavior Change)',
                            description: `Server behavior changed when injecting SQL syntax, suggesting possible vulnerability. ${sqli.description}`,
                            evidence: `Payload "${sqli.payload}" caused status ${status} at ${testUrl}`,
                            endpoint: endpoint.url,
                            remediation: 'Investigate the endpoint for SQL injection. Use parameterized queries.',
                            cweId: 'CWE-89',
                            owaspCategory: 'A03:2021 Injection'
                        });
                    }

                    await this.safeDelay();
                } catch (e) {
                    logger.debug(`SQLi test failed: ${e}`);
                }
            }
        }
    }

    /**
     * Phase 5: Rate Limiting Check
     */
    private async testRateLimiting(page: Page): Promise<void> {
        // Find auth-related endpoints
        const authEndpoints = this.recon.endpoints.filter(e =>
            e.url.includes('/login') ||
            e.url.includes('/signup') ||
            e.url.includes('/auth') ||
            e.url.includes('/password')
        );

        // Also check the main auth page if found
        const loginUrl = authEndpoints.find(e => e.type === 'auth')?.url ||
            `${new URL(this.recon.endpoints[0]?.url || 'https://example.com').origin}/login`;

        this.testCount++;

        try {
            // Make 5 rapid requests (safe number that won't DoS)
            const results: number[] = [];
            for (let i = 0; i < 5; i++) {
                const response = await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                results.push(response?.status() || 0);
                // Very short delay between requests to test rate limiting
                await new Promise(r => setTimeout(r, 100));
            }

            // Check if any request was rate limited (429) or blocked
            const rateLimited = results.some(s => s === 429 || s === 403);

            if (!rateLimited) {
                this.findings.push({
                    id: 'rate-limit-1',
                    category: 'rate-limit',
                    severity: 'MEDIUM',
                    title: 'Missing Rate Limiting on Authentication Endpoint',
                    description: 'No rate limiting detected on the login endpoint. This could allow brute force attacks.',
                    evidence: `5 rapid requests to ${loginUrl} all returned 200 status`,
                    endpoint: loginUrl,
                    remediation: 'Implement rate limiting using Vercel Edge Middleware or Supabase Auth rate limits. Recommended: 5 attempts per minute per IP.',
                    cweId: 'CWE-307',
                    owaspCategory: 'A07:2021 Identification and Authentication Failures'
                });
            } else {
                logger.info(`  ✓ Rate limiting detected on ${loginUrl}`);
            }
        } catch (e) {
            logger.debug(`Rate limiting test failed: ${e}`);
        }

        await this.safeDelay();
    }

    /**
     * Phase 6: Authentication Bypass Checks
     */
    private async testAuthenticationBypass(page: Page): Promise<void> {
        // Find protected endpoints
        const protectedEndpoints = this.recon.endpoints.filter(e =>
            e.requiresAuth ||
            e.url.includes('/dashboard') ||
            e.url.includes('/settings') ||
            e.url.includes('/admin')
        );

        for (const endpoint of protectedEndpoints.slice(0, 3)) {
            this.testCount++;

            try {
                // Clear cookies to simulate unauthenticated access
                const cookies = await page.context().cookies();
                await page.context().clearCookies();

                const response = await page.goto(endpoint.url, { waitUntil: 'domcontentloaded', timeout: 10000 });
                const status = response?.status() || 0;
                const content = await page.content();
                const finalUrl = page.url();

                // Check if we were redirected to login (correct behavior)
                const redirectedToLogin = finalUrl.includes('login') || finalUrl.includes('signin') || finalUrl.includes('auth');

                // Check if protected content is exposed
                if (status === 200 && !redirectedToLogin) {
                    // Look for signs of actual protected content
                    const hasProtectedContent =
                        content.includes('dashboard') ||
                        content.includes('settings') ||
                        content.includes('profile') && content.length > 2000;

                    if (hasProtectedContent) {
                        this.findings.push({
                            id: `auth-bypass-${this.findings.length + 1}`,
                            category: 'auth',
                            severity: 'CRITICAL',
                            title: 'Authentication Bypass - Protected Content Exposed',
                            description: 'Protected endpoint accessible without authentication. User data may be exposed.',
                            evidence: `Accessed ${endpoint.url} without cookies, received ${status} status with protected content`,
                            endpoint: endpoint.url,
                            remediation: 'Implement middleware authentication checks. Use Next.js middleware or Supabase RLS policies.',
                            cweId: 'CWE-287',
                            owaspCategory: 'A07:2021 Identification and Authentication Failures'
                        });
                    }
                }

                // Restore cookies
                if (cookies.length > 0) {
                    await page.context().addCookies(cookies);
                }

                await this.safeDelay();
            } catch (e) {
                logger.debug(`Auth bypass test failed: ${e}`);
            }
        }
    }

    /**
     * Phase 7: Information Disclosure
     */
    private async testInformationDisclosure(page: Page): Promise<void> {
        const baseUrl = new URL(this.recon.endpoints[0]?.url || 'https://example.com').origin;

        // Common sensitive paths to check
        const sensitivePaths = [
            '/.env',
            '/.git/config',
            '/api/debug',
            '/api/health',
            '/_next/static/chunks/pages/_app',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt'
        ];

        for (const pathToCheck of sensitivePaths) {
            this.testCount++;

            try {
                const testUrl = `${baseUrl}${pathToCheck}`;
                const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                const status = response?.status() || 0;

                if (status === 200) {
                    const content = await page.content();

                    // Check for exposed .env
                    if (pathToCheck === '/.env' && (content.includes('=') || content.includes('API_KEY'))) {
                        this.findings.push({
                            id: 'info-env',
                            category: 'info-disclosure',
                            severity: 'CRITICAL',
                            title: 'Environment File Exposed',
                            description: '.env file is publicly accessible and may contain secrets.',
                            evidence: `${testUrl} returned 200 with environment variables`,
                            endpoint: testUrl,
                            remediation: 'Block access to .env files via web server configuration or Next.js middleware.',
                            cweId: 'CWE-200',
                            owaspCategory: 'A01:2021 Broken Access Control'
                        });
                    }

                    // Check for exposed .git
                    if (pathToCheck === '/.git/config' && content.includes('[core]')) {
                        this.findings.push({
                            id: 'info-git',
                            category: 'info-disclosure',
                            severity: 'HIGH',
                            title: 'Git Repository Exposed',
                            description: '.git directory is publicly accessible. Source code may be downloadable.',
                            evidence: `${testUrl} returned git configuration`,
                            endpoint: testUrl,
                            remediation: 'Block access to .git directory. Add to .gitignore and web server rules.',
                            cweId: 'CWE-200',
                            owaspCategory: 'A01:2021 Broken Access Control'
                        });
                    }

                    // Check for debug endpoints
                    if (pathToCheck.includes('debug') && (content.includes('stack') || content.includes('error'))) {
                        this.findings.push({
                            id: 'info-debug',
                            category: 'info-disclosure',
                            severity: 'MEDIUM',
                            title: 'Debug Endpoint Exposed',
                            description: 'Debug information is publicly accessible.',
                            evidence: `${testUrl} returned debug information`,
                            endpoint: testUrl,
                            remediation: 'Disable debug endpoints in production. Use environment checks.',
                            cweId: 'CWE-200',
                            owaspCategory: 'A05:2021 Security Misconfiguration'
                        });
                    }
                }

                await this.safeDelay();
            } catch (e) {
                // Timeout or error is expected for most paths
                logger.debug(`Info disclosure test for ${pathToCheck}: ${e}`);
            }
        }

        // Check for verbose error pages
        this.testCount++;
        try {
            const errorTestUrl = `${baseUrl}/this-page-does-not-exist-scm-test-${Date.now()}`;
            await page.goto(errorTestUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
            const content = await page.content();

            // Check for stack traces or framework info in 404
            if (content.includes('stack') || content.includes('at ') || content.includes('node_modules')) {
                this.findings.push({
                    id: 'info-error',
                    category: 'info-disclosure',
                    severity: 'LOW',
                    title: 'Verbose Error Messages',
                    description: 'Error pages reveal stack traces or framework information.',
                    evidence: `404 page at ${errorTestUrl} contains technical details`,
                    endpoint: errorTestUrl,
                    remediation: 'Implement custom error pages. Set NODE_ENV=production to disable verbose errors.',
                    cweId: 'CWE-209',
                    owaspCategory: 'A05:2021 Security Misconfiguration'
                });
            }
        } catch (e) {
            logger.debug(`Error page test failed: ${e}`);
        }

        // Check cookie security
        for (const cookie of this.recon.cookies) {
            if (cookie.name.includes('session') || cookie.name.includes('auth') || cookie.name.includes('token')) {
                this.testCount++;

                if (!cookie.httpOnly) {
                    this.findings.push({
                        id: `cookie-httponly-${cookie.name}`,
                        category: 'info-disclosure',
                        severity: 'MEDIUM',
                        title: 'Authentication Cookie Missing HttpOnly Flag',
                        description: `Cookie "${cookie.name}" is accessible via JavaScript, making it vulnerable to XSS theft.`,
                        evidence: `Cookie ${cookie.name}: HttpOnly=${cookie.httpOnly}`,
                        endpoint: baseUrl,
                        remediation: 'Set HttpOnly flag on all authentication cookies.',
                        cweId: 'CWE-1004',
                        owaspCategory: 'A05:2021 Security Misconfiguration'
                    });
                }

                if (!cookie.secure) {
                    this.findings.push({
                        id: `cookie-secure-${cookie.name}`,
                        category: 'info-disclosure',
                        severity: 'MEDIUM',
                        title: 'Authentication Cookie Missing Secure Flag',
                        description: `Cookie "${cookie.name}" can be transmitted over unencrypted connections.`,
                        evidence: `Cookie ${cookie.name}: Secure=${cookie.secure}`,
                        endpoint: baseUrl,
                        remediation: 'Set Secure flag on all authentication cookies.',
                        cweId: 'CWE-614',
                        owaspCategory: 'A05:2021 Security Misconfiguration'
                    });
                }

                if (cookie.sameSite === 'None' || cookie.sameSite === 'none') {
                    this.findings.push({
                        id: `cookie-samesite-${cookie.name}`,
                        category: 'csrf',
                        severity: 'MEDIUM',
                        title: 'Authentication Cookie with Weak SameSite Policy',
                        description: `Cookie "${cookie.name}" has SameSite=None, potentially vulnerable to CSRF.`,
                        evidence: `Cookie ${cookie.name}: SameSite=${cookie.sameSite}`,
                        endpoint: baseUrl,
                        remediation: 'Set SameSite=Strict or SameSite=Lax for authentication cookies.',
                        cweId: 'CWE-352',
                        owaspCategory: 'A01:2021 Broken Access Control'
                    });
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // HELPER METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private analyzeEndpoint(url: string, baseUrl: string): EndpointInfo | null {
        try {
            const parsed = new URL(url);
            const path = parsed.pathname;

            let type: EndpointInfo['type'] = 'page';
            if (path.includes('/api/')) type = 'api';
            if (path.includes('/auth') || path.includes('/login') || path.includes('/signup')) type = 'auth';
            if (path.match(/\.(js|css|png|jpg|svg|ico)$/)) type = 'static';

            const requiresAuth =
                path.includes('/dashboard') ||
                path.includes('/settings') ||
                path.includes('/admin') ||
                path.includes('/account');

            return {
                url,
                method: 'GET',
                type,
                requiresAuth,
                parameters: Array.from(parsed.searchParams.keys())
            };
        } catch {
            return null;
        }
    }

    private extractParameters(url: string): void {
        try {
            const parsed = new URL(url);

            // URL parameters
            for (const [name, value] of parsed.searchParams) {
                const type = this.classifyParameter(name);
                this.recon.parameters.push({
                    name,
                    location: 'url',
                    endpoint: url,
                    type
                });
            }

            // Path parameters (e.g., /profile/{username})
            const pathParts = parsed.pathname.split('/');
            for (const part of pathParts) {
                if (part.match(/^[a-f0-9-]{36}$/i)) { // UUID
                    this.recon.parameters.push({
                        name: 'id',
                        location: 'url',
                        endpoint: url,
                        type: 'id'
                    });
                } else if (part.match(/^\d+$/)) { // Numeric ID
                    this.recon.parameters.push({
                        name: 'id',
                        location: 'url',
                        endpoint: url,
                        type: 'id'
                    });
                }
            }
        } catch {
            // Invalid URL, skip
        }
    }

    private classifyParameter(name: string): ParameterInfo['type'] {
        const lowerName = name.toLowerCase();
        if (lowerName.includes('id') || lowerName === 'uuid') return 'id';
        if (lowerName.includes('search') || lowerName === 'q' || lowerName === 'query') return 'search';
        if (lowerName.includes('filter') || lowerName.includes('sort') || lowerName.includes('page')) return 'filter';
        if (lowerName.includes('token') || lowerName.includes('auth') || lowerName.includes('key')) return 'auth';
        return 'other';
    }

    private mutateUrlForIDOR(url: string): string | null {
        try {
            const parsed = new URL(url);
            const pathParts = parsed.pathname.split('/');

            // Find and mutate username/ID part
            for (let i = 0; i < pathParts.length; i++) {
                // If this looks like a username, try a different one
                if (pathParts[i - 1] === 'profile' || pathParts[i - 1] === 'user') {
                    pathParts[i] = 'admin'; // Try common privileged username
                    parsed.pathname = pathParts.join('/');
                    return parsed.toString();
                }

                // If this looks like a numeric ID
                if (pathParts[i].match(/^\d+$/)) {
                    pathParts[i] = '1'; // Try ID 1 (often admin)
                    parsed.pathname = pathParts.join('/');
                    return parsed.toString();
                }

                // If this looks like a UUID
                if (pathParts[i].match(/^[a-f0-9-]{36}$/i)) {
                    pathParts[i] = '00000000-0000-0000-0000-000000000000';
                    parsed.pathname = pathParts.join('/');
                    return parsed.toString();
                }
            }

            return null;
        } catch {
            return null;
        }
    }

    private injectPayload(baseUrl: string, paramName: string, payload: string): string {
        try {
            const parsed = new URL(baseUrl);
            parsed.searchParams.set(paramName, payload);
            return parsed.toString();
        } catch {
            return `${baseUrl}?${paramName}=${encodeURIComponent(payload)}`;
        }
    }

    private injectSQLiPayload(baseUrl: string, payload: string): string {
        try {
            const parsed = new URL(baseUrl);
            const pathParts = parsed.pathname.split('/');

            // Inject into path parameter (username/ID)
            for (let i = 0; i < pathParts.length; i++) {
                if (pathParts[i - 1] === 'profile' || pathParts[i - 1] === 'user' || pathParts[i].match(/^\d+$/)) {
                    pathParts[i] = pathParts[i] + payload;
                    parsed.pathname = pathParts.join('/');
                    return parsed.toString();
                }
            }

            // Fallback: add as query parameter
            parsed.searchParams.set('id', payload);
            return parsed.toString();
        } catch {
            return `${baseUrl}?id=${encodeURIComponent(payload)}`;
        }
    }

    private async safeDelay(): Promise<void> {
        // Rate limit our own testing to avoid triggering WAF
        const delay = randomInt(1000, 3000); // 1-3 seconds
        await new Promise(r => setTimeout(r, delay));
    }

    /**
     * Get findings
     */
    getFindings(): SecurityFinding[] {
        return [...this.findings];
    }

    /**
     * Get reconnaissance data
     */
    getReconData(): ReconData {
        return { ...this.recon };
    }
}

export default SecurityAssessment;
