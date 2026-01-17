/**
 * PII Scanner (Data Loss Prevention)
 * Detects exposure of personally identifiable information in DOM and Network traffic.
 */

import { Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';
import { retry, ScannerRetryOptions } from '../utils/retry.js';

export interface PiiFinding {
    type: 'SSN' | 'CreditCard' | 'PhoneNumber';
    risk: 'High';
    description: string;
    source: string; // 'DOM' or 'Network'
    matchedPattern: string;
    redactedMatch: string;
    timestamp: string;
    location?: string; // Selector or URL
}

export class PiiScanner implements IScanner {
    readonly name = 'PiiScanner';
    private findings: PiiFinding[] = [];
    private domScanTimer: NodeJS.Timeout | null = null;
    private domScanScheduledAt = 0;
    private whitelist: RegExp[] = [
        // Exempt test data (e.g., specific test users or phone numbers)
        /555-01\d{2}/, // Example test phone numbers
        /4242-4242-4242-4242/, // Stripe test card
    ];

    /**
     * Regex Patterns for PII detection
     */
    private patterns = {
        // SSN: Matches AAA-GG-SSSS patterns
        ssn: /\b(?!000|666|9\d{2})([0-9]{3})-(?!00)([0-9]{2})-(?!0000)([0-9]{4})\b/g,

        // Credit Card: Matches major card formats (Visa, MasterCard, Amex, Discover)
        // Groups of 4 digits, 4-6-5, etc. Separators: space or dash.
        creditCard: /\b(?:\d[ -]*?){13,16}\b/g,

        // Phone: US Formats (123) 456-7890, 123-456-7890, 123.456.7890, +1 123 456 7890
        phone: /(?:\+?1[-. ]?)?\(?([2-9][0-8][0-9])\)?[-. ]?([2-9][0-9]{2})[-. ]?([0-9]{4})\b/g
    };

    /**
     * Page Creation Hook - Scan DOM text
     */
    async onPageCreated(page: Page): Promise<void> {
        // Listen for load event to scan static content
        page.on('load', async () => {
            this.scheduleDomScan(page);
        });

        // Optional: Periodic scan for dynamic content changes (e.g., every 2s)
        // For performance, we'll stick to 'load' and maybe 'visible' assertions in user flows
    }

    /**
     * Network Response Hook - Scan response bodies
     */
    async onResponse(response: Response): Promise<void> {
        try {
            const contentType = response.headers()['content-type'] || '';
            const url = response.url();

            // Skip non-text responses (images, fonts, media)
            if (!contentType.includes('text') && !contentType.includes('json') && !contentType.includes('xml')) {
                return;
            }

            // Get text body
            const text = await retry(() => response.text(), { ...ScannerRetryOptions, logger });
            this.scanText(text, 'Network', url);

        } catch {
            // Ignore body read errors (redirects, empty bodies)
        }
    }

    /**
     * Scan visible text in the DOM
     */
    private async scanDom(page: Page): Promise<void> {
        try {
            // Get all visible text from the body
            const content = await page.innerText('body');
            this.scanText(content, 'DOM', 'body');

            // Should ideally check inputs specifically if requirements demanded it
            // const inputValues = await page.evaluate(() => ...);
        } catch (error) {
            logger.warn(`PiiScanner DOM scan failed: ${error}`);
        }
    }

    private scheduleDomScan(page: Page): void {
        const now = Date.now();
        this.domScanScheduledAt = now;

        if (this.domScanTimer) {
            clearTimeout(this.domScanTimer);
        }

        this.domScanTimer = setTimeout(async () => {
            if (this.domScanScheduledAt !== now) return;
            await this.scanDom(page);
        }, 250);
    }

    /**
     * Core Scan Logic
     */
    private scanText(text: string, source: 'DOM' | 'Network', location: string): void {
        this.checkPattern(text, this.patterns.ssn, 'SSN', source, location);
        this.checkPattern(text, this.patterns.creditCard, 'CreditCard', source, location);
        this.checkPattern(text, this.patterns.phone, 'PhoneNumber', source, location);
    }

    private checkPattern(text: string, regex: RegExp, type: PiiFinding['type'], source: string, location: string): void {
        const matches = text.match(regex);
        if (!matches) return;

        for (const match of matches) {
            const cleanMatch = match.replace(/[-. ()]/g, ''); // strip separators

            // Additional Validation
            if (this.isWhitelisted(match)) continue;

            if (type === 'CreditCard' && !this.luhnCheck(cleanMatch)) {
                continue; // Invalid card number (likely random digits)
            }
            // For SSN: Simple regex is usually enough for "potential" finding, standard area checks are complex
            // For Phone: Regex handles most format constraints

            // Create Finding
            const finding: PiiFinding = {
                type,
                risk: 'High',
                description: `Potential ${type} found in ${source} content`,
                source,
                location,
                matchedPattern: type,
                redactedMatch: this.redact(match),
                timestamp: new Date().toISOString()
            };

            // Deduplicate simple findings
            const isDuplicate = this.findings.some(f =>
                f.type === finding.type &&
                f.redactedMatch === finding.redactedMatch &&
                f.location === finding.location
            );

            if (!isDuplicate) {
                this.findings.push(finding);
                logger.warn(`[PiiScanner] Detected ${type} in ${source}: ${finding.redactedMatch} at ${location}`);
            }
        }
    }

    /**
     * Check if a match is whitelisted
     */
    private isWhitelisted(match: string): boolean {
        return this.whitelist.some(pattern => pattern.test(match));
    }

    /**
     * Luhn Algorithm for Credit Card Validation
     */
    private luhnCheck(value: string): boolean {
        if (/[^0-9-\s]+/.test(value)) return false;

        let nCheck = 0;
        let nDigit = 0;
        let bEven = false;
        value = value.replace(/\D/g, "");

        for (let n = value.length - 1; n >= 0; n--) {
            const cDigit = value.charAt(n);
            nDigit = parseInt(cDigit, 10);

            if (bEven) {
                if ((nDigit *= 2) > 9) nDigit -= 9;
            }

            nCheck += nDigit;
            bEven = !bEven;
        }

        return (nCheck % 10) == 0;
    }

    /**
     * Redact sensitive data for logging
     */
    private redact(value: string): string {
        if (value.length < 4) return '***';
        const visible = value.slice(-4);
        return `***-${visible}`;
    }

    /**
     * Get Results
     */
    getResults(): PiiFinding[] {
        return this.findings;
    }

    /**
     * Clear Findings
     */
    clear(): void {
        this.findings = [];
    }
}
