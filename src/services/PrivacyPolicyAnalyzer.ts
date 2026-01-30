/**
 * Privacy Policy Analyzer
 *
 * Service that analyzes privacy policy pages for compliance:
 * - GDPR Article 13/14 disclosure requirements
 * - CCPA notice requirements
 * - Cookie disclosure vs actual cookies comparison
 * - Tracker disclosure vs detected trackers comparison
 * - Data retention disclosure
 * - DPO contact information
 */

import type { BrowserContext, Page } from 'playwright';
import { logger } from '../utils/logger.js';
import { safeEvaluate } from '../utils/page-helpers.js';

export interface PrivacyPolicyFinding {
    type: 'missing-disclosure' | 'tracker-mismatch' | 'cookie-mismatch' | 'gdpr-missing' | 'ccpa-missing' | 'incomplete-policy' | 'stale-policy';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    gdprArticle?: string;
    remediation?: string;
}

interface PolicyContent {
    url: string;
    text: string;
    lastModified: string | null;
    language: string;
}

interface CookieInfo {
    name: string;
    domain: string;
    purpose: string;
    thirdParty: boolean;
}

// GDPR Article 13 required disclosures
const GDPR_ARTICLE_13_CHECKS = [
    {
        id: 'controller-identity',
        article: 'Art. 13(1)(a)',
        description: 'Identity and contact details of the controller',
        patterns: [/data\s*controller/i, /responsible\s*party/i, /operated\s*by/i, /company\s*name/i, /registered\s*at/i, /controller\s*is/i],
    },
    {
        id: 'dpo-contact',
        article: 'Art. 13(1)(b)',
        description: 'Contact details of the Data Protection Officer',
        patterns: [/data\s*protection\s*officer/i, /\bDPO\b/, /dpo@/i, /privacy@/i, /datenschutzbeauftragter/i],
    },
    {
        id: 'processing-purpose',
        article: 'Art. 13(1)(c)',
        description: 'Purposes of the processing',
        patterns: [/purpose\s*(of|for)\s*(processing|collection)/i, /we\s*(use|collect|process)\s*(your\s*)?(personal\s*)?data\s*(for|to)/i, /why\s*we\s*collect/i],
    },
    {
        id: 'legal-basis',
        article: 'Art. 13(1)(c)',
        description: 'Legal basis for the processing',
        patterns: [/legal\s*basis/i, /legitimate\s*interest/i, /consent/i, /contractual\s*(obligation|necessity)/i, /legal\s*obligation/i, /Art(icle)?\.\s*6/i],
    },
    {
        id: 'data-recipients',
        article: 'Art. 13(1)(e)',
        description: 'Recipients or categories of recipients',
        patterns: [/recipients/i, /third\s*part(y|ies)/i, /share.*data\s*with/i, /service\s*providers/i, /sub-?processors/i, /we\s*(may\s*)?disclose/i],
    },
    {
        id: 'international-transfers',
        article: 'Art. 13(1)(f)',
        description: 'Transfers to third countries',
        patterns: [/international\s*transfer/i, /cross-?border/i, /transfer.*outside/i, /adequate.*protection/i, /standard\s*contractual\s*clauses/i, /privacy\s*shield/i],
    },
    {
        id: 'retention-period',
        article: 'Art. 13(2)(a)',
        description: 'Data retention period or criteria',
        patterns: [/retention\s*period/i, /how\s*long\s*we\s*(keep|store|retain)/i, /delete.*after/i, /stored\s*for/i, /retain.*data/i],
    },
    {
        id: 'data-subject-rights',
        article: 'Art. 13(2)(b)',
        description: 'Data subject rights (access, rectification, erasure)',
        patterns: [/right\s*to\s*access/i, /right\s*to\s*(be\s*)?forgotten/i, /right\s*to\s*(erasure|deletion)/i, /right\s*to\s*rectif/i, /right\s*to\s*portability/i, /data\s*subject\s*rights/i, /your\s*rights/i],
    },
    {
        id: 'right-to-withdraw',
        article: 'Art. 13(2)(c)',
        description: 'Right to withdraw consent',
        patterns: [/withdraw\s*(your\s*)?consent/i, /revoke\s*consent/i, /opt[\s-]*out/i],
    },
    {
        id: 'supervisory-authority',
        article: 'Art. 13(2)(d)',
        description: 'Right to lodge a complaint with a supervisory authority',
        patterns: [/supervisory\s*authority/i, /data\s*protection\s*authority/i, /lodge\s*a\s*complaint/i, /information\s*commissioner/i, /\bCNIL\b/i, /\bICO\b/],
    },
];

// CCPA required disclosures
const CCPA_CHECKS = [
    {
        id: 'categories-collected',
        description: 'Categories of personal information collected',
        patterns: [/categories\s*of\s*(personal\s*)?information/i, /types\s*of\s*(personal\s*)?data/i, /information\s*we\s*collect/i],
    },
    {
        id: 'sale-of-info',
        description: 'Right to opt-out of sale of personal information',
        patterns: [/do\s*not\s*sell/i, /opt[\s-]*out\s*of\s*sale/i, /sale\s*of.*personal\s*information/i, /selling\s*your\s*data/i],
    },
    {
        id: 'right-to-know',
        description: 'Right to know what data is collected',
        patterns: [/right\s*to\s*know/i, /right\s*to\s*request/i, /access\s*your\s*(personal\s*)?information/i],
    },
    {
        id: 'right-to-delete',
        description: 'Right to request deletion',
        patterns: [/right\s*to\s*delet/i, /request\s*deletion/i, /delete\s*your\s*(personal\s*)?information/i],
    },
    {
        id: 'non-discrimination',
        description: 'Non-discrimination for exercising rights',
        patterns: [/non[\s-]*discrimination/i, /not\s*discriminat/i, /equal\s*service/i],
    },
];

// Known tracker domains
const KNOWN_TRACKER_DOMAINS = [
    { domain: 'google-analytics.com', name: 'Google Analytics' },
    { domain: 'googletagmanager.com', name: 'Google Tag Manager' },
    { domain: 'facebook.net', name: 'Facebook Pixel' },
    { domain: 'facebook.com/tr', name: 'Facebook Tracking' },
    { domain: 'doubleclick.net', name: 'Google DoubleClick' },
    { domain: 'hotjar.com', name: 'Hotjar' },
    { domain: 'mixpanel.com', name: 'Mixpanel' },
    { domain: 'segment.io', name: 'Segment' },
    { domain: 'segment.com', name: 'Segment' },
    { domain: 'amplitude.com', name: 'Amplitude' },
    { domain: 'fullstory.com', name: 'FullStory' },
    { domain: 'sentry.io', name: 'Sentry' },
    { domain: 'intercom.io', name: 'Intercom' },
    { domain: 'hubspot.com', name: 'HubSpot' },
    { domain: 'tiktok.com/i18n', name: 'TikTok Pixel' },
    { domain: 'clarity.ms', name: 'Microsoft Clarity' },
    { domain: 'linkedin.com/px', name: 'LinkedIn Insight' },
];

// Privacy policy link patterns
const PRIVACY_LINK_PATTERNS = [
    /privacy\s*(policy|notice|statement)/i,
    /datenschutz(erkl[aä]rung)?/i,
    /politique\s*de\s*confidentialit[eé]/i,
    /data\s*protection/i,
    /cookie\s*policy/i,
];

export class PrivacyPolicyAnalyzer {
    private findings: PrivacyPolicyFinding[] = [];

    /**
     * Analyze privacy policy for a site.
     */
    async analyze(
        page: Page,
        context: BrowserContext,
        detectedTrackerDomains: string[] = []
    ): Promise<PrivacyPolicyFinding[]> {
        this.findings = [];
        const baseUrl = page.url();

        // Find privacy policy link
        const policyUrl = await this.findPrivacyPolicyLink(page);
        if (!policyUrl) {
            this.addFinding({
                type: 'missing-disclosure',
                severity: 'high',
                description: 'No privacy policy link found on the page',
                evidence: `Page ${baseUrl} has no visible privacy policy link`,
                url: baseUrl,
                gdprArticle: 'Art. 13/14',
                remediation: 'Add a visible link to your privacy policy, typically in the footer',
            });
            return this.findings;
        }

        // Navigate to and extract policy content
        const policy = await this.extractPolicyContent(page, policyUrl);
        if (!policy) {
            this.addFinding({
                type: 'incomplete-policy',
                severity: 'high',
                description: 'Could not access or extract privacy policy content',
                evidence: `Privacy policy at ${policyUrl} is not accessible`,
                url: policyUrl,
                remediation: 'Ensure privacy policy page is publicly accessible',
            });
            return this.findings;
        }

        // Run all checks
        this.checkGdprCompliance(policy);
        this.checkCcpaCompliance(policy);
        await this.checkCookieDisclosure(policy, context);
        this.checkTrackerDisclosure(policy, detectedTrackerDomains);

        logger.info(`[PrivacyPolicyAnalyzer] ${this.findings.length} findings for ${baseUrl}`);
        return [...this.findings];
    }

    /**
     * Find a privacy policy link on the page.
     */
    private async findPrivacyPolicyLink(page: Page): Promise<string | null> {
        return safeEvaluate<string | null>(page, () => {
            const links = document.querySelectorAll('a');
            const patterns = [
                /privacy/i,
                /datenschutz/i,
                /confidentialit/i,
                /data.protection/i,
            ];

            for (const link of links) {
                const text = link.textContent?.trim() || '';
                const href = link.getAttribute('href') || '';

                for (const pattern of patterns) {
                    if (pattern.test(text) || pattern.test(href)) {
                        return link.href; // Full resolved URL
                    }
                }
            }
            return null;
        });
    }

    /**
     * Navigate to privacy policy page and extract text content.
     */
    private async extractPolicyContent(page: Page, policyUrl: string): Promise<PolicyContent | null> {
        try {
            const currentUrl = page.url();
            await page.goto(policyUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });

            const content = await safeEvaluate<PolicyContent>(page, () => {
                // Try to find the main content area
                const main = document.querySelector('main, article, [role="main"], .content, .policy, .privacy-policy');
                const textSource = main || document.body;

                return {
                    url: window.location.href,
                    text: textSource.textContent?.trim().slice(0, 50000) || '',
                    lastModified: document.querySelector('meta[name="last-modified"]')?.getAttribute('content') ||
                        document.querySelector('time')?.getAttribute('datetime') || null,
                    language: document.documentElement.lang || 'unknown',
                };
            });

            // Navigate back to original page
            try {
                await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
            } catch {
                // Best effort to navigate back
            }

            return content;
        } catch (error) {
            logger.debug(`[PrivacyPolicyAnalyzer] Failed to extract policy: ${(error as Error).message}`);
            return null;
        }
    }

    /**
     * Check GDPR Article 13 required disclosures.
     */
    private checkGdprCompliance(policy: PolicyContent): void {
        const text = policy.text;

        for (const check of GDPR_ARTICLE_13_CHECKS) {
            const found = check.patterns.some(pattern => pattern.test(text));
            if (!found) {
                this.addFinding({
                    type: 'gdpr-missing',
                    severity: check.id === 'controller-identity' || check.id === 'processing-purpose' ? 'high' : 'medium',
                    description: `GDPR ${check.article}: Missing disclosure - ${check.description}`,
                    evidence: `Privacy policy does not appear to contain ${check.description.toLowerCase()}`,
                    url: policy.url,
                    gdprArticle: check.article,
                    remediation: `Add ${check.description.toLowerCase()} to your privacy policy as required by GDPR ${check.article}`,
                });
            }
        }
    }

    /**
     * Check CCPA required disclosures.
     */
    private checkCcpaCompliance(policy: PolicyContent): void {
        const text = policy.text;

        for (const check of CCPA_CHECKS) {
            const found = check.patterns.some(pattern => pattern.test(text));
            if (!found) {
                this.addFinding({
                    type: 'ccpa-missing',
                    severity: check.id === 'sale-of-info' ? 'high' : 'medium',
                    description: `CCPA: Missing disclosure - ${check.description}`,
                    evidence: `Privacy policy does not address ${check.description.toLowerCase()}`,
                    url: policy.url,
                    remediation: `Add ${check.description.toLowerCase()} to your privacy policy for CCPA compliance`,
                });
            }
        }
    }

    /**
     * Compare disclosed cookies vs actual cookies set by the site.
     */
    private async checkCookieDisclosure(policy: PolicyContent, context: BrowserContext): Promise<void> {
        try {
            const cookies = await context.cookies();
            if (cookies.length === 0) return;

            const policyText = policy.text.toLowerCase();

            // Check for any cookie disclosure section
            const hasCookieSection = /cookie/i.test(policyText) || /tracking\s*technolog/i.test(policyText);
            if (!hasCookieSection && cookies.length > 1) {
                this.addFinding({
                    type: 'cookie-mismatch',
                    severity: 'high',
                    description: 'Privacy policy lacks cookie disclosure but site sets cookies',
                    evidence: `${cookies.length} cookies set but no cookie section found in privacy policy`,
                    url: policy.url,
                    gdprArticle: 'Art. 13(1)(c)',
                    remediation: 'Add a cookie disclosure section listing all cookies, their purposes, and retention periods',
                });
                return;
            }

            // Check third-party cookies
            const mainDomain = new URL(policy.url).hostname.replace(/^www\./, '');
            const thirdPartyCookies = cookies.filter(c => !c.domain.includes(mainDomain));

            if (thirdPartyCookies.length > 0) {
                const undisclosedDomains: string[] = [];
                for (const cookie of thirdPartyCookies) {
                    const cookieDomain = cookie.domain.replace(/^\./, '');
                    if (!policyText.includes(cookieDomain.toLowerCase())) {
                        undisclosedDomains.push(cookieDomain);
                    }
                }

                const unique = [...new Set(undisclosedDomains)];
                if (unique.length > 0) {
                    this.addFinding({
                        type: 'cookie-mismatch',
                        severity: 'medium',
                        description: 'Third-party cookies set but not disclosed in privacy policy',
                        evidence: `Undisclosed cookie domains: ${unique.slice(0, 10).join(', ')}`,
                        url: policy.url,
                        gdprArticle: 'Art. 13(1)(e)',
                        remediation: 'Disclose all third-party cookie providers in your privacy policy',
                    });
                }
            }
        } catch {
            // Context may be closed
        }
    }

    /**
     * Compare disclosed trackers vs detected trackers.
     */
    private checkTrackerDisclosure(policy: PolicyContent, detectedDomains: string[]): void {
        const policyText = policy.text.toLowerCase();

        for (const domain of detectedDomains) {
            const tracker = KNOWN_TRACKER_DOMAINS.find(t => domain.includes(t.domain));
            if (tracker) {
                const trackerNameLower = tracker.name.toLowerCase();
                const trackerDomainLower = tracker.domain.toLowerCase();

                if (!policyText.includes(trackerNameLower) && !policyText.includes(trackerDomainLower)) {
                    this.addFinding({
                        type: 'tracker-mismatch',
                        severity: 'high',
                        description: `Tracker "${tracker.name}" detected but not disclosed in privacy policy`,
                        evidence: `${tracker.name} (${tracker.domain}) was loaded but not mentioned in the privacy policy`,
                        url: policy.url,
                        gdprArticle: 'Art. 13(1)(e)',
                        remediation: `Disclose the use of ${tracker.name} in your privacy policy and obtain appropriate consent`,
                    });
                }
            }
        }
    }

    private addFinding(finding: PrivacyPolicyFinding): void {
        const key = `${finding.type}:${finding.description.slice(0, 60)}`;
        if (!this.findings.some(f => `${f.type}:${f.description.slice(0, 60)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): PrivacyPolicyFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
    }
}
