/**
 * SupabaseSecurityScanner Service
 *
 * Detects Supabase security misconfigurations from the client-side:
 *
 * 1. CRITICAL: service_role key leaked in JS bundles (full DB access)
 * 2. HIGH: Supabase URL exposed without proper RLS (testable)
 * 3. MEDIUM: anon key with overly permissive policies
 * 4. INFO: Detects Supabase usage for reporting
 *
 * Note: Cannot check server-side RLS policies, but can detect:
 * - Leaked privileged keys
 * - Open REST endpoints
 * - Unprotected storage buckets
 * 
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry';
import { logger } from '../utils/logger';

export interface SupabaseSecurityIssue {
    type: 'service_role_leaked' | 'anon_key_exposed' | 'open_storage' | 'rls_bypass_possible' | 'insecure_realtime';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    description: string;
    evidence: string;
    remediation: string;
}

export interface SupabaseDetection {
    detected: boolean;
    projectUrl?: string;
    anonKeyFound?: string;
    issues: SupabaseSecurityIssue[];
}

// Supabase key patterns
const SUPABASE_PATTERNS = {
    // Project URL pattern: https://<project-ref>.supabase.co
    projectUrl: /https:\/\/([a-z0-9-]+)\.supabase\.co/gi,

    // Anon key (expected in client) - JWT starting with eyJ
    anonKey: /(?:supabase|SUPABASE)(?:_ANON)?_KEY['\":\s=]+['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?/gi,

    // Service role key (CRITICAL - should NEVER be in client)
    serviceRoleKey: /(?:service_role|SERVICE_ROLE|supabase_service)(?:_key)?['\":\s=]+['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?/gi,

    // Direct service role in createClient call
    createClientServiceRole: /createClient\s*\(\s*['"][^'"]+['"]\s*,\s*['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?\s*,?\s*\{[^}]*(?:auth|persistSession)/gi,
};

export class SupabaseSecurityScanner implements IScanner {
    readonly name = 'SupabaseSecurityScanner';

    private issues: SupabaseSecurityIssue[] = [];
    private detectedProjectUrl: string | null = null;
    private detectedAnonKey: string | null = null;
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
        logger.info('  🔐 Supabase Security Scanner attached');
    }

    /**
     * Called for each network response - scan for Supabase patterns
     */
    async onResponse(response: Response): Promise<void> {
        try {
            const url = response.url();
            const contentType = response.headers()['content-type'] || '';

            // Scan JavaScript and JSON files
            const isScriptOrConfig =
                contentType.includes('javascript') ||
                contentType.includes('json') ||
                url.endsWith('.js') ||
                url.includes('_next/static');

            if (isScriptOrConfig && !this.scannedUrls.has(url)) {
                this.scannedUrls.add(url);

                // Skip known safe externals
                if (this.isExternalCDN(url)) return;

                try {
                    const content = await response.text();
                    this.scanContent(url, content);
                } catch (e) {
                    logger.debug(`SupabaseScanner: Could not read ${url.substring(0, 60)}`);
                }
            }
        } catch (e) {
            logger.debug(`SupabaseScanner error: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    /**
     * Called during shutdown
     */
    onClose(): void {
        logger.debug(`SupabaseScanner: Found ${this.issues.length} security issues`);
    }

    /**
     * Get collected results
     */
    getResults(): SupabaseDetection {
        return {
            detected: this.detectedProjectUrl !== null,
            projectUrl: this.detectedProjectUrl || undefined,
            anonKeyFound: this.detectedAnonKey || undefined,
            issues: this.issues
        };
    }

    /**
     * Clear scanner state
     */
    clear(): void {
        this.issues = [];
        this.detectedProjectUrl = null;
        this.detectedAnonKey = null;
        this.scannedUrls.clear();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Legacy API (for backward compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @deprecated Use ScannerRegistry.register() instead
     * Legacy attach method for backward compatibility
     */
    attach(page: Page): void {
        this.onPageCreated(page);

        page.on('response', async (response) => {
            await this.onResponse(response);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Core Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Scan content for Supabase patterns
     */
    private scanContent(sourceUrl: string, content: string): void {
        // Detect Supabase project URL
        const projectMatch = SUPABASE_PATTERNS.projectUrl.exec(content);
        if (projectMatch) {
            this.detectedProjectUrl = projectMatch[0];
            SUPABASE_PATTERNS.projectUrl.lastIndex = 0;
        }

        // Detect anon key (expected, but log for awareness)
        SUPABASE_PATTERNS.anonKey.lastIndex = 0;
        const anonMatch = SUPABASE_PATTERNS.anonKey.exec(content);
        if (anonMatch && anonMatch[1]) {
            this.detectedAnonKey = this.maskKey(anonMatch[1]);
            // Anon key is expected, but we track it
            logger.debug(`Supabase anon key detected (expected): ${this.detectedAnonKey}`);
        }

        // CRITICAL: Check for service_role key
        SUPABASE_PATTERNS.serviceRoleKey.lastIndex = 0;
        const serviceMatch = SUPABASE_PATTERNS.serviceRoleKey.exec(content);
        if (serviceMatch && serviceMatch[1]) {
            const maskedKey = this.maskKey(serviceMatch[1]);

            // Verify it's actually a service_role key by decoding JWT header
            if (this.isServiceRoleKey(serviceMatch[1])) {
                logger.error(`🚨 CRITICAL: Supabase service_role key LEAKED in ${sourceUrl}`);

                this.issues.push({
                    type: 'service_role_leaked',
                    severity: 'CRITICAL',
                    description: 'Supabase service_role key exposed in client-side JavaScript. This key bypasses ALL Row Level Security and has full database access.',
                    evidence: `Key found in: ${sourceUrl}\nMasked: ${maskedKey}`,
                    remediation: '1. IMMEDIATELY rotate the service_role key in Supabase dashboard\n2. Remove from client code - use server-side API routes\n3. Audit database for unauthorized changes\n4. Enable Supabase audit logging'
                });
            }
        }

        // Check for createClient with service role pattern
        SUPABASE_PATTERNS.createClientServiceRole.lastIndex = 0;
        const createMatch = SUPABASE_PATTERNS.createClientServiceRole.exec(content);
        if (createMatch) {
            logger.warn(`⚠️ Supabase createClient with privileged options in ${sourceUrl}`);

            this.issues.push({
                type: 'rls_bypass_possible',
                severity: 'HIGH',
                description: 'Supabase client initialized with potentially privileged configuration. Review auth options.',
                evidence: `Found in: ${sourceUrl}`,
                remediation: 'Ensure createClient only uses anon key on client-side. Move privileged operations to server-side API routes.'
            });
        }
    }

    /**
     * Check if a JWT is a service_role key by decoding the payload
     */
    private isServiceRoleKey(jwt: string): boolean {
        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) return false;

            // Decode payload (second part)
            const payload = JSON.parse(
                Buffer.from(parts[1], 'base64').toString('utf-8')
            );

            // Service role keys have role: "service_role"
            return payload.role === 'service_role';
        } catch {
            // If we can't decode, check by variable name context (already matched pattern)
            return true; // Assume worst case
        }
    }

    /**
     * Run active tests against detected Supabase instance
     * These are READ-ONLY probes that check for misconfigurations
     */
    async runActiveTests(page: Page): Promise<void> {
        if (!this.detectedProjectUrl) {
            logger.debug('No Supabase project detected - skipping active tests');
            return;
        }

        logger.info(`  🔍 Running Supabase security probes on ${this.detectedProjectUrl}`);

        // Test 1: Check if storage bucket allows public listing
        await this.testStorageBucketListing(page);

        // Test 2: Check if REST API allows unauthenticated reads
        await this.testRestApiAccess(page);
    }

    /**
     * Test if storage buckets allow public listing (common misconfiguration)
     */
    private async testStorageBucketListing(page: Page): Promise<void> {
        if (!this.detectedProjectUrl) return;

        try {
            const storageUrl = `${this.detectedProjectUrl}/storage/v1/bucket`;

            const response = await page.evaluate(async (url) => {
                try {
                    const res = await fetch(url, { method: 'GET' });
                    return { status: res.status, ok: res.ok };
                } catch {
                    return { status: 0, ok: false };
                }
            }, storageUrl);

            if (response.ok) {
                logger.warn(`⚠️ Supabase storage bucket listing is PUBLIC`);
                this.issues.push({
                    type: 'open_storage',
                    severity: 'MEDIUM',
                    description: 'Supabase storage bucket listing is publicly accessible. Attackers can enumerate all buckets.',
                    evidence: `GET ${storageUrl} returned 200 OK`,
                    remediation: 'Configure storage bucket policies in Supabase dashboard to restrict listing. Set appropriate RLS policies on storage.objects table.'
                });
            }
        } catch (e) {
            logger.debug(`Storage test failed: ${e}`);
        }
    }

    /**
     * Test if REST API allows reads without authentication
     */
    private async testRestApiAccess(page: Page): Promise<void> {
        if (!this.detectedProjectUrl) return;

        // Common table names to probe (read-only)
        const commonTables = ['users', 'profiles', 'posts', 'items', 'loadouts'];

        for (const table of commonTables) {
            try {
                const restUrl = `${this.detectedProjectUrl}/rest/v1/${table}?limit=1`;

                const response = await page.evaluate(async (url) => {
                    try {
                        const res = await fetch(url, {
                            method: 'GET',
                            headers: { 'Accept': 'application/json' }
                        });
                        const text = await res.text();
                        return {
                            status: res.status,
                            hasData: text.length > 2 && !text.includes('permission denied')
                        };
                    } catch {
                        return { status: 0, hasData: false };
                    }
                }, restUrl);

                if (response.status === 200 && response.hasData) {
                    logger.warn(`⚠️ Table "${table}" accessible without authentication`);
                    this.issues.push({
                        type: 'rls_bypass_possible',
                        severity: 'HIGH',
                        description: `Table "${table}" returns data without authentication. RLS may be disabled or misconfigured.`,
                        evidence: `GET ${restUrl} returned data`,
                        remediation: `Enable RLS on table "${table}" with: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; Then create appropriate policies.`
                    });
                    break; // Found one, that's enough
                }
            } catch (e) {
                logger.debug(`REST API test for ${table} failed: ${e}`);
            }
        }
    }

    /**
     * Mask a key for safe logging
     */
    private maskKey(key: string): string {
        if (key.length <= 20) return '***REDACTED***';
        return `${key.substring(0, 10)}...${key.substring(key.length - 6)}`;
    }

    /**
     * Skip external CDN scripts
     */
    private isExternalCDN(url: string): boolean {
        const cdnDomains = [
            'googleapis.com',
            'gstatic.com',
            'cloudflare.com',
            'unpkg.com',
            'jsdelivr.net',
            'cdnjs.cloudflare.com'
        ];
        return cdnDomains.some(d => url.includes(d));
    }

    /**
     * Get issues only
     */
    getIssues(): SupabaseSecurityIssue[] {
        return [...this.issues];
    }
}

export default SupabaseSecurityScanner;
