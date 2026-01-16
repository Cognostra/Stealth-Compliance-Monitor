/**
 * SecretScanner Service
 *
 * Intercepts JavaScript assets loaded by the browser and scans them for
 * leaked API keys and secrets.
 *
 * Patterns Scanned:
 * - Cloud: AWS, Google Cloud
 * - Payment: Stripe (live & test)
 * - BaaS: Supabase service_role, Firebase server keys
 * - Database: Connection strings (postgres, mysql, mongodb, redis)
 * - Auth: GitHub, Slack, Discord tokens
 * - Communication: SendGrid, Twilio
 * - Generic: Hardcoded secrets and JWTs
 * 
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface LeakedSecret {
    type: string;
    fileUrl: string;
    maskedValue: string;
    risk: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

const SECRET_PATTERNS = [
    // === Cloud Provider Keys ===
    {
        name: 'Google API Key',
        regex: /AIza[0-9A-Za-z-_]{35}/g,
        risk: 'HIGH'
    },
    {
        name: 'AWS Access Key',
        regex: /AKIA[0-9A-Z]{16}/g,
        risk: 'CRITICAL'
    },
    {
        name: 'AWS Secret Key',
        regex: /(?:aws_secret|AWS_SECRET)[_A-Z]*['\":\s=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?/gi,
        risk: 'CRITICAL'
    },

    // === Payment Providers ===
    {
        name: 'Stripe Live Secret Key',
        regex: /sk_live_[0-9a-zA-Z]{24,}/g,
        risk: 'CRITICAL'
    },
    {
        name: 'Stripe Test Secret Key',
        regex: /sk_test_[0-9a-zA-Z]{24,}/g,
        risk: 'MEDIUM'
    },

    // === Supabase ===
    {
        name: 'Supabase Service Role Key',
        regex: /(?:service_role|SERVICE_ROLE)[_A-Za-z]*['\":\s=]+['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?/gi,
        risk: 'CRITICAL'
    },

    // === Firebase ===
    {
        name: 'Firebase Server Key',
        regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
        risk: 'CRITICAL'
    },
    {
        name: 'Private Key (RSA/PEM)',
        regex: /-----BEGIN (RSA )?PRIVATE KEY-----/g,
        risk: 'CRITICAL'
    },

    // === Database Connection Strings ===
    {
        name: 'Database Connection String',
        regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'\"]+/gi,
        risk: 'CRITICAL'
    },

    // === Auth Tokens ===
    {
        name: 'GitHub Token',
        regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
        risk: 'CRITICAL'
    },
    {
        name: 'Slack Token',
        regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
        risk: 'HIGH'
    },
    {
        name: 'Discord Bot Token',
        regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
        risk: 'HIGH'
    },

    // === Communication Services ===
    {
        name: 'SendGrid API Key',
        regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
        risk: 'HIGH'
    },
    {
        name: 'Twilio Auth Token',
        regex: /(?:twilio|TWILIO)[_A-Za-z]*(?:auth|AUTH)[_A-Za-z]*['\":\s=]+['\"]?([a-f0-9]{32})['\"]?/gi,
        risk: 'HIGH'
    },

    // === Generic Secrets ===
    {
        name: 'Hardcoded JWT',
        regex: /(?:bearer|token|jwt|auth)['\":\s=]+['\"]?(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})['\"]?/gi,
        risk: 'MEDIUM'
    },
    {
        name: 'Generic Secret Assignment',
        regex: /(?:secret|password|passwd|api_key|apiKey|private_key|auth_token)['\"_A-Za-z]*\s*[:=]\s*['\"]([A-Za-z0-9!@#$%^&*()_+=\-]{16,})['\"](?!\s*\+)/gi,
        risk: 'MEDIUM'
    },
];

export class SecretScanner implements IScanner {
    readonly name = 'SecretScanner';

    private foundSecrets: LeakedSecret[] = [];
    private scannedUrls: Set<string> = new Set();
    private page: Page | null = null;

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Called when page is created
     */
    onPageCreated(page: Page): void {
        this.page = page;
        logger.info('  🕵️ Secret Scanner attached');
    }

    /**
     * Called for each network response - scan JavaScript files
     */
    async onResponse(response: Response): Promise<void> {
        try {
            const url = response.url();
            const contentType = response.headers()['content-type'] || '';

            // Only scan JavaScript files
            if (
                (contentType.includes('javascript') || url.endsWith('.js')) &&
                !this.scannedUrls.has(url)
            ) {
                this.scannedUrls.add(url);

                // Skip external vendor scripts to reduce noise/cost
                if (this.isSafeExternal(url)) return;

                try {
                    const content = await response.text();
                    this.scanContent(url, content);
                } catch (e) {
                    logger.debug(`SecretScanner: Could not read response body for ${url.substring(0, 80)}: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        } catch (e) {
            logger.debug(`SecretScanner: Error processing response: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    /**
     * Called during shutdown
     */
    onClose(): void {
        logger.debug(`SecretScanner: Found ${this.foundSecrets.length} potential secrets`);
    }

    /**
     * Get collected results
     */
    getResults(): LeakedSecret[] {
        return this.getSecrets();
    }

    /**
     * Clear scanner state
     */
    clear(): void {
        this.foundSecrets = [];
        this.scannedUrls.clear();
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

        page.on('response', async (response) => {
            await this.onResponse(response);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Core Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Scan text content against regex patterns
     */
    private scanContent(url: string, content: string): void {
        SECRET_PATTERNS.forEach(pattern => {
            let match;
            // Reset regex index
            pattern.regex.lastIndex = 0;

            while ((match = pattern.regex.exec(content)) !== null) {
                const fullMatch = match[0];
                // If capture group exists (for generic regex), use it, otherwise use full match
                const secretValue = match[1] || fullMatch;

                // Skip if this looks false positive (too short or common words)
                if (this.isFalsePositive(secretValue)) continue;

                const masked = this.maskSecret(secretValue);

                logger.error(`🚨 DETECTED LEAKED SECRET [${pattern.name}] in ${url}`);

                this.foundSecrets.push({
                    type: pattern.name,
                    fileUrl: url,
                    maskedValue: masked,
                    risk: pattern.risk as LeakedSecret['risk']
                });
            }
        });
    }

    /**
     * Mask a secret value for logging
     * Example: AIzaSy...A1b2
     */
    private maskSecret(value: string): string {
        if (value.length <= 8) return '********';
        return `${value.substring(0, 6)}...${value.substring(value.length - 4)}`;
    }

    /**
     * Check if the value is likely a false positive
     */
    private isFalsePositive(val: string): boolean {
        // Common variable names matching generic regex
        const commonWords = ['undefined', 'null', 'placeholder', 'your_api_key'];
        if (commonWords.includes(val.toLowerCase())) return true;
        return false;
    }

    /**
     * Ignore safe external domains (optional, strictly configured)
     */
    private isSafeExternal(url: string): boolean {
        const safeDomains = [
            'google-analytics.com',
            'googletagmanager.com',
            'node_modules' // in local dev
        ];
        return safeDomains.some(d => url.includes(d));
    }

    public getSecrets(): LeakedSecret[] {
        return this.foundSecrets;
    }
}
