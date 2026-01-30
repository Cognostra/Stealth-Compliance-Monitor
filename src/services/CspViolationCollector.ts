/**
 * CSP (Content Security Policy) Violation Collector
 *
 * IScanner that analyzes Content-Security-Policy headers and collects violations:
 * - Missing CSP entirely
 * - Dangerous directives (unsafe-eval, unsafe-inline, wildcard sources)
 * - Missing critical directives
 * - CSP bypass patterns (JSONP endpoints, data: URIs)
 * - Real-time violation collection via securitypolicyviolation DOM events
 */

import type { Page, Request, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';
import { isDocumentResponse } from '../utils/response-reader.js';

export interface CspFinding {
    type: 'missing-csp' | 'unsafe-eval' | 'unsafe-inline' | 'wildcard-source' | 'violation' | 'bypass' | 'missing-directive' | 'report-only';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    directive?: string;
    blockedUri?: string;
    remediation?: string;
}

// Known JSONP endpoints that bypass CSP
const KNOWN_CSP_BYPASSES = [
    '*.google.com',
    '*.googleapis.com',
    'cdnjs.cloudflare.com',
    '*.cloudflare.com',
    '*.amazonaws.com',
    '*.azurewebsites.net',
];

// Critical CSP directives that should be present
const REQUIRED_DIRECTIVES = [
    'default-src',
    'script-src',
    'object-src',
    'base-uri',
];

const IMPORTANT_DIRECTIVES = [
    'style-src',
    'img-src',
    'font-src',
    'connect-src',
    'frame-src',
    'frame-ancestors',
    'form-action',
];

export class CspViolationCollector implements IScanner {
    readonly name = 'CspViolationCollector';
    private findings: CspFinding[] = [];
    private analyzedUrls: Set<string> = new Set();
    private pages: WeakSet<Page> = new WeakSet();
    private violationCount = 0;

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);

        // Listen for CSP violation reports via page console
        page.on('console', msg => {
            const text = msg.text();
            if (text.includes('Content Security Policy') || text.includes('content-security-policy')) {
                this.violationCount++;
                this.addFinding({
                    type: 'violation',
                    severity: 'medium',
                    description: 'CSP violation detected during page execution',
                    evidence: text.slice(0, 500),
                    url: page.url(),
                    remediation: 'Update CSP to either allow the resource or remove the offending code',
                });
            }
        });

        logger.debug('[CspViolationCollector] Attached to page');
    }

    /**
     * Inject a securitypolicyviolation event listener to collect violations.
     */
    async injectViolationListener(page: Page): Promise<void> {
        try {
            await page.evaluate(() => {
                (window as unknown as Record<string, unknown>).__cspViolations = [];
                document.addEventListener('securitypolicyviolation', (e) => {
                    const violations = (window as unknown as Record<string, unknown[]>).__cspViolations;
                    if (violations.length < 50) {
                        violations.push({
                            blockedURI: e.blockedURI,
                            violatedDirective: e.violatedDirective,
                            effectiveDirective: e.effectiveDirective,
                            originalPolicy: e.originalPolicy?.slice(0, 500),
                            disposition: e.disposition,
                            documentURI: e.documentURI,
                        });
                    }
                });
            });
        } catch {
            // Page might not support this
        }
    }

    /**
     * Collect violations captured by the injected listener.
     */
    async collectViolations(page: Page): Promise<CspFinding[]> {
        const newFindings: CspFinding[] = [];
        try {
            const violations = await page.evaluate(() =>
                (window as unknown as Record<string, unknown[]>).__cspViolations || []
            ) as Array<{
                blockedURI: string;
                violatedDirective: string;
                effectiveDirective: string;
                disposition: string;
                documentURI: string;
            }>;

            for (const v of violations) {
                const finding: CspFinding = {
                    type: 'violation',
                    severity: v.disposition === 'enforce' ? 'medium' : 'low',
                    description: `CSP ${v.disposition} violation: ${v.violatedDirective}`,
                    evidence: `Blocked URI: ${v.blockedURI}, Directive: ${v.effectiveDirective}`,
                    url: v.documentURI || page.url(),
                    directive: v.effectiveDirective,
                    blockedUri: v.blockedURI,
                    remediation: `Review CSP directive "${v.effectiveDirective}" and either allow the resource or remove the code`,
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }
        } catch {
            // Page may have navigated
        }
        return newFindings;
    }

    async onResponse(response: Response): Promise<void> {
        if (!isDocumentResponse(response)) return;

        const url = response.url();
        if (this.analyzedUrls.has(url)) return;
        this.analyzedUrls.add(url);

        const headers = await response.allHeaders();
        const csp = headers['content-security-policy'];
        const cspReportOnly = headers['content-security-policy-report-only'];

        if (!csp && !cspReportOnly) {
            this.addFinding({
                type: 'missing-csp',
                severity: 'high',
                description: 'No Content-Security-Policy header found',
                evidence: `Document ${url} has no CSP header`,
                url,
                remediation: "Add Content-Security-Policy header with at least: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
            });
            return;
        }

        if (!csp && cspReportOnly) {
            this.addFinding({
                type: 'report-only',
                severity: 'medium',
                description: 'CSP is in report-only mode - violations are not enforced',
                evidence: `Document ${url} uses Content-Security-Policy-Report-Only instead of enforcing`,
                url,
                remediation: 'Switch from Content-Security-Policy-Report-Only to Content-Security-Policy for enforcement',
            });
        }

        const policyToAnalyze = csp || cspReportOnly || '';
        this.analyzeCspPolicy(policyToAnalyze, url);
    }

    private analyzeCspPolicy(policy: string, url: string): void {
        const directives = this.parseDirectives(policy);

        // Check for missing critical directives
        for (const required of REQUIRED_DIRECTIVES) {
            if (!directives.has(required) && required !== 'default-src') {
                // If default-src exists, other directives fall back to it
                if (!directives.has('default-src')) {
                    this.addFinding({
                        type: 'missing-directive',
                        severity: required === 'script-src' ? 'high' : 'medium',
                        description: `Missing critical CSP directive: ${required}`,
                        evidence: `CSP policy on ${url} lacks "${required}" directive`,
                        url,
                        directive: required,
                        remediation: `Add "${required}" directive to your CSP. Recommended: ${required} 'self'`,
                    });
                }
            }
        }

        // Check each directive for dangerous values
        for (const [directive, values] of directives) {
            const valuesStr = values.join(' ');

            // unsafe-eval
            if (values.includes("'unsafe-eval'")) {
                this.addFinding({
                    type: 'unsafe-eval',
                    severity: directive === 'script-src' || directive === 'default-src' ? 'high' : 'medium',
                    description: `CSP directive "${directive}" allows 'unsafe-eval' - enables eval() and related functions`,
                    evidence: `${directive}: ${valuesStr}`,
                    url,
                    directive,
                    remediation: `Remove 'unsafe-eval' from ${directive}. Refactor code to avoid eval(), Function(), and setTimeout/setInterval with strings`,
                });
            }

            // unsafe-inline
            if (values.includes("'unsafe-inline'") && !values.some(v => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
                this.addFinding({
                    type: 'unsafe-inline',
                    severity: directive === 'script-src' || directive === 'default-src' ? 'high' : 'low',
                    description: `CSP directive "${directive}" allows 'unsafe-inline' without nonce/hash - weakens CSP significantly`,
                    evidence: `${directive}: ${valuesStr}`,
                    url,
                    directive,
                    remediation: `Replace 'unsafe-inline' with nonce-based or hash-based CSP: ${directive} 'nonce-<random>'`,
                });
            }

            // Wildcard sources
            if (values.includes('*')) {
                this.addFinding({
                    type: 'wildcard-source',
                    severity: directive === 'script-src' || directive === 'default-src' ? 'critical' : 'medium',
                    description: `CSP directive "${directive}" uses wildcard (*) - allows loading from any source`,
                    evidence: `${directive}: ${valuesStr}`,
                    url,
                    directive,
                    remediation: `Replace wildcard with specific trusted domains in ${directive}`,
                });
            }

            // data: URIs
            if (values.includes('data:') && (directive === 'script-src' || directive === 'default-src')) {
                this.addFinding({
                    type: 'bypass',
                    severity: 'high',
                    description: `CSP directive "${directive}" allows data: URIs - can be used for XSS bypass`,
                    evidence: `${directive}: ${valuesStr}`,
                    url,
                    directive,
                    remediation: `Remove "data:" from ${directive}. Use data: only in img-src if needed`,
                });
            }

            // Known JSONP bypass domains
            for (const bypassDomain of KNOWN_CSP_BYPASSES) {
                if (values.some(v => v.includes(bypassDomain.replace('*.', '')))) {
                    if (directive === 'script-src' || directive === 'default-src') {
                        this.addFinding({
                            type: 'bypass',
                            severity: 'medium',
                            description: `CSP allows ${bypassDomain} which has known JSONP endpoints usable for CSP bypass`,
                            evidence: `${directive} includes domain matching ${bypassDomain}`,
                            url,
                            directive,
                            remediation: `Use specific paths instead of broad domain allowlists, or use nonce-based CSP`,
                        });
                        break;
                    }
                }
            }
        }
    }

    private parseDirectives(policy: string): Map<string, string[]> {
        const directives = new Map<string, string[]>();
        const parts = policy.split(';').map(s => s.trim()).filter(Boolean);

        for (const part of parts) {
            const tokens = part.split(/\s+/);
            const name = tokens[0].toLowerCase();
            const values = tokens.slice(1);
            directives.set(name, values);
        }

        return directives;
    }

    private addFinding(finding: CspFinding): void {
        const key = `${finding.type}:${finding.url}:${finding.directive || ''}`;
        if (!this.findings.some(f => `${f.type}:${f.url}:${f.directive || ''}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): CspFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.analyzedUrls.clear();
        this.violationCount = 0;
    }

    onClose(): void {
        logger.info(`  [CSP] ${this.findings.length} findings, ${this.violationCount} violations observed`);
    }
}
