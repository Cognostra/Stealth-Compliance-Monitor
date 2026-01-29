/**
 * FintechScanner - Financial & Crypto Compliance Scanner
 *
 * Detects fintech-specific security issues:
 * - Crypto-jacking scripts (known miner domains, WebSocket mining pools)
 * - PCI-DSS violations (missing security headers, credit card data in storage)
 * - Wallet drainer heuristics (suspicious Web3 calls, known drainer patterns)
 *
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, Response, Request } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface FintechFinding {
    type: 'cryptojacking' | 'pci-dss' | 'wallet-drainer';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    remediation?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

const KNOWN_MINER_DOMAINS = [
    'coinhive.com',
    'coin-hive.com',
    'cryptoloot.pro',
    'crypto-loot.com',
    'minero.cc',
    'jsecoin.com',
    'webminepool.com',
    'ppoi.org',
    'coinlab.biz',
    'rocks.io',
    'minecrunch.co',
    'minemytraffic.com',
    'coinimp.com',
    'mineralt.io',
    'webmine.cz',
    'authedmine.com',
    'coinhive-manager.com',
];

const MINING_POOL_PATTERNS = [
    'stratum+tcp://',
    'stratum+ssl://',
    'pool.minergate.com',
    'xmr.pool.',
    'moneroocean.stream',
    'nanopool.org',
    'hashvault.pro',
    'supportxmr.com',
];

const KNOWN_DRAINER_SIGNATURES = [
    'setApprovalForAll',
    'transferFrom',
    'permit(',
    'increaseAllowance',
    'multicall',
    'atomicMatch_',
];

const DRAINER_DOMAINS = [
    'inferno-drainer',
    'angel-drainer',
    'pink-drainer',
    'monkey-drainer',
    'venom-drainer',
    'pussy-drainer',
];

const PCI_REQUIRED_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-XSS-Protection',
];

/** Luhn-valid credit card number patterns (Visa, MC, Amex, Discover) */
const CREDIT_CARD_REGEX = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/;

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class FintechScanner implements IScanner {
    readonly name = 'FintechScanner';

    private findings: FintechFinding[] = [];
    private page: Page | null = null;
    private checkedHeaders = new Set<string>();
    private checkedRequests = new Set<string>();
    private customMinerDomains: string[];

    constructor(customMinerDomains: string[] = []) {
        this.customMinerDomains = customMinerDomains;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    onPageCreated(page: Page): void {
        if (this.page === page) return;
        this.page = page;
        logger.info('  💰 Fintech Scanner attached to browser session');
    }

    async onRequest(request: Request): Promise<void> {
        const url = request.url();
        if (this.checkedRequests.has(url)) return;
        this.checkedRequests.add(url);

        this.checkCryptoJackingRequest(url);
        this.checkWalletDrainerRequest(url);
    }

    async onResponse(response: Response): Promise<void> {
        const url = response.url();

        // Check PCI headers on document responses only
        if (response.request().resourceType() === 'document' && !this.checkedHeaders.has(url)) {
            this.checkedHeaders.add(url);
            await this.checkPciHeaders(response);
        }

        // Check script responses for mining/drainer code
        if (response.request().resourceType() === 'script') {
            await this.checkScriptContent(response);
        }
    }

    onClose(): void {
        logger.debug(`FintechScanner: Collected ${this.findings.length} findings`);
    }

    getResults(): FintechFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.checkedHeaders.clear();
        this.checkedRequests.clear();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PAGE-LEVEL CHECKS (called after page load)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Run all page-level fintech checks. Call after page navigation.
     */
    async runPageChecks(page: Page): Promise<FintechFinding[]> {
        const pageFindings: FintechFinding[] = [];

        const storageFindings = await this.checkCreditCardInStorage(page);
        pageFindings.push(...storageFindings);

        const autocompleteFindings = await this.checkPaymentAutocomplete(page);
        pageFindings.push(...autocompleteFindings);

        const web3Findings = await this.checkWeb3Injections(page);
        pageFindings.push(...web3Findings);

        const minerFindings = await this.checkMiningActivity(page);
        pageFindings.push(...minerFindings);

        this.findings.push(...pageFindings);
        return pageFindings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CRYPTO-JACKING DETECTION
    // ═══════════════════════════════════════════════════════════════════════════

    private checkCryptoJackingRequest(url: string): void {
        const allMinerDomains = [...KNOWN_MINER_DOMAINS, ...this.customMinerDomains];

        for (const domain of allMinerDomains) {
            if (url.includes(domain)) {
                this.findings.push({
                    type: 'cryptojacking',
                    severity: 'critical',
                    description: `Request to known crypto-mining domain: ${domain}`,
                    evidence: `URL: ${url}`,
                    url,
                    remediation: 'Remove all references to crypto-mining scripts. Add the domain to your Content-Security-Policy blocklist.',
                });
                return;
            }
        }

        for (const pattern of MINING_POOL_PATTERNS) {
            if (url.includes(pattern)) {
                this.findings.push({
                    type: 'cryptojacking',
                    severity: 'critical',
                    description: `Connection to mining pool detected: ${pattern}`,
                    evidence: `URL: ${url}`,
                    url,
                    remediation: 'Block WebSocket connections to mining pools via CSP connect-src directive.',
                });
                return;
            }
        }
    }

    private async checkScriptContent(response: Response): Promise<void> {
        try {
            const body = await response.text();
            if (body.length > 5_000_000) return; // Skip very large scripts

            // Check for mining library signatures
            const minerSignatures = [
                'CoinHive.Anonymous',
                'CoinHive.Token',
                'CoinHive.User',
                'coinhive.min.js',
                'miner.start(',
                'CryptoNoter',
                'deepMiner',
                'CoinImp.Anonymous',
            ];

            for (const sig of minerSignatures) {
                if (body.includes(sig)) {
                    this.findings.push({
                        type: 'cryptojacking',
                        severity: 'critical',
                        description: `Crypto-mining library detected in script: ${sig}`,
                        evidence: `Script URL: ${response.url()}`,
                        url: response.url(),
                        remediation: 'Remove the mining script immediately. This hijacks user CPU resources without consent.',
                    });
                    break;
                }
            }

            // Check for WebAssembly + crypto.subtle co-usage (common in obfuscated miners)
            if (body.includes('WebAssembly') && body.includes('crypto.subtle')) {
                const hasHashingPatterns = body.includes('SHA-256') || body.includes('sha256') ||
                    body.includes('cryptonight') || body.includes('randomx');
                if (hasHashingPatterns) {
                    this.findings.push({
                        type: 'cryptojacking',
                        severity: 'high',
                        description: 'Suspicious WebAssembly + crypto.subtle + hashing pattern detected (potential obfuscated miner)',
                        evidence: `Script URL: ${response.url()}`,
                        url: response.url(),
                        remediation: 'Investigate the script for unauthorized mining. WebAssembly with crypto hashing is a common obfuscation technique for miners.',
                    });
                }
            }
        } catch {
            // Response body may not be available
        }
    }

    private async checkMiningActivity(page: Page): Promise<FintechFinding[]> {
        const findings: FintechFinding[] = [];
        try {
            const miningIndicators = await page.evaluate(() => {
                const indicators: string[] = [];

                // Check for known mining global objects
                const globals = ['CoinHive', 'coinhive', 'CoinImp', 'Client', 'deepMiner', 'CryptoNoter'];
                for (const g of globals) {
                    if ((window as Record<string, unknown>)[g] !== undefined) {
                        indicators.push(`Global mining object found: ${g}`);
                    }
                }

                // Check for high CPU usage via performance API
                if (typeof performance !== 'undefined' && performance.getEntriesByType) {
                    const longTasks = performance.getEntriesByType('longtask');
                    if (longTasks.length > 10) {
                        indicators.push(`Excessive long tasks detected: ${longTasks.length} (potential mining activity)`);
                    }
                }

                return indicators;
            });

            for (const indicator of miningIndicators) {
                findings.push({
                    type: 'cryptojacking',
                    severity: 'critical',
                    description: indicator,
                    evidence: `Page: ${page.url()}`,
                    url: page.url(),
                    remediation: 'Remove mining scripts and audit all third-party script inclusions.',
                });
            }
        } catch {
            // Page evaluation may fail
        }
        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PCI-DSS COMPLIANCE CHECKS
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkPciHeaders(response: Response): Promise<void> {
        try {
            const headers = await response.allHeaders();
            const headerKeys = Object.keys(headers).map(h => h.toLowerCase());

            for (const required of PCI_REQUIRED_HEADERS) {
                if (!headerKeys.includes(required.toLowerCase())) {
                    this.findings.push({
                        type: 'pci-dss',
                        severity: required === 'Strict-Transport-Security' ? 'high' : 'medium',
                        description: `Missing PCI-DSS required header: ${required}`,
                        evidence: `URL: ${response.url()}`,
                        url: response.url(),
                        remediation: `Add the ${required} header to all server responses. This is required for PCI-DSS compliance.`,
                    });
                }
            }
        } catch {
            // Headers may not be available
        }
    }

    private async checkCreditCardInStorage(page: Page): Promise<FintechFinding[]> {
        const findings: FintechFinding[] = [];
        try {
            const storageData = await page.evaluate(() => {
                const data: { source: string; key: string; value: string }[] = [];

                // Check localStorage
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key) {
                        const value = localStorage.getItem(key) || '';
                        data.push({ source: 'localStorage', key, value });
                    }
                }

                // Check sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key) {
                        const value = sessionStorage.getItem(key) || '';
                        data.push({ source: 'sessionStorage', key, value });
                    }
                }

                return data;
            });

            for (const item of storageData) {
                if (CREDIT_CARD_REGEX.test(item.value)) {
                    findings.push({
                        type: 'pci-dss',
                        severity: 'critical',
                        description: `Credit card number pattern detected in ${item.source}`,
                        evidence: `Key: "${item.key}" in ${item.source} (value redacted)`,
                        url: page.url(),
                        remediation: 'Never store credit card numbers in browser storage. Use a PCI-compliant payment processor (Stripe, Braintree) to handle card data server-side.',
                    });
                }
            }
        } catch {
            // Storage access may fail
        }
        return findings;
    }

    private async checkPaymentAutocomplete(page: Page): Promise<FintechFinding[]> {
        const findings: FintechFinding[] = [];
        try {
            const issues = await page.evaluate(() => {
                const paymentSelectors = [
                    'input[name*="card"]',
                    'input[name*="credit"]',
                    'input[name*="cc-"]',
                    'input[autocomplete="cc-number"]',
                    'input[autocomplete="cc-exp"]',
                    'input[autocomplete="cc-csc"]',
                    'input[type="tel"][name*="card"]',
                ];

                const found: { selector: string; autocomplete: string | null }[] = [];
                for (const sel of paymentSelectors) {
                    const elements = document.querySelectorAll(sel);
                    elements.forEach(el => {
                        const input = el as HTMLInputElement;
                        const ac = input.getAttribute('autocomplete');
                        // autocomplete should be "off" for payment fields per PCI-DSS
                        if (ac !== 'off') {
                            found.push({
                                selector: sel,
                                autocomplete: ac,
                            });
                        }
                    });
                }
                return found;
            });

            for (const issue of issues) {
                findings.push({
                    type: 'pci-dss',
                    severity: 'medium',
                    description: `Payment input field without autocomplete="off"`,
                    evidence: `Selector: ${issue.selector}, autocomplete="${issue.autocomplete || 'not set'}"`,
                    url: page.url(),
                    remediation: 'Set autocomplete="off" on all payment-related input fields to prevent browsers from caching sensitive financial data.',
                });
            }
        } catch {
            // DOM evaluation may fail
        }
        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WALLET DRAINER DETECTION
    // ═══════════════════════════════════════════════════════════════════════════

    private checkWalletDrainerRequest(url: string): void {
        const lowerUrl = url.toLowerCase();
        for (const domain of DRAINER_DOMAINS) {
            if (lowerUrl.includes(domain)) {
                this.findings.push({
                    type: 'wallet-drainer',
                    severity: 'critical',
                    description: `Connection to known wallet drainer infrastructure: ${domain}`,
                    evidence: `URL: ${url}`,
                    url,
                    remediation: 'Immediately remove all references to this domain. It is associated with cryptocurrency wallet draining attacks.',
                });
                return;
            }
        }
    }

    private async checkWeb3Injections(page: Page): Promise<FintechFinding[]> {
        const findings: FintechFinding[] = [];
        try {
            const web3Issues = await page.evaluate((drainerSigs: string[]) => {
                const issues: { type: string; evidence: string }[] = [];

                // Check for ethereum provider injection
                const win = window as Record<string, unknown>;
                if (win.ethereum) {
                    issues.push({
                        type: 'ethereum_provider',
                        evidence: 'window.ethereum object detected',
                    });
                }

                // Look for suspicious Web3 method calls in inline scripts
                const scripts = document.querySelectorAll('script:not([src])');
                scripts.forEach(script => {
                    const content = script.textContent || '';

                    // Check for eth_sendTransaction with suspicious patterns
                    if (content.includes('eth_sendTransaction') || content.includes('eth_signTypedData')) {
                        // Check if it's requesting approval for all tokens
                        for (const sig of drainerSigs) {
                            if (content.includes(sig)) {
                                issues.push({
                                    type: 'drainer_signature',
                                    evidence: `Suspicious method call: ${sig}`,
                                });
                            }
                        }
                    }

                    // Check for suspicious permit/approval patterns
                    if (content.includes('approve(') && content.includes('0xffffffff')) {
                        issues.push({
                            type: 'unlimited_approval',
                            evidence: 'Unlimited token approval pattern detected (0xffffffff)',
                        });
                    }
                });

                return issues;
            }, KNOWN_DRAINER_SIGNATURES);

            for (const issue of web3Issues) {
                const severityMap: Record<string, 'critical' | 'high' | 'medium'> = {
                    'drainer_signature': 'critical',
                    'unlimited_approval': 'critical',
                    'ethereum_provider': 'low' as 'medium', // Informational - just presence isn't malicious
                };

                findings.push({
                    type: 'wallet-drainer',
                    severity: severityMap[issue.type] || 'high',
                    description: `Web3 security issue: ${issue.type.replace(/_/g, ' ')}`,
                    evidence: issue.evidence,
                    url: page.url(),
                    remediation: issue.type === 'ethereum_provider'
                        ? 'Verify that the Web3 provider is legitimately required. If not, remove the injection.'
                        : 'Investigate immediately. This pattern is commonly used in wallet draining attacks.',
                });
            }
        } catch {
            // Page evaluation may fail
        }
        return findings;
    }
}

export default FintechScanner;
