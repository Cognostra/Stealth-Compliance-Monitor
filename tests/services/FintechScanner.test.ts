import { FintechScanner, FintechFinding } from '../../src/services/FintechScanner.js';

// Mock Playwright types
const createMockResponse = (overrides: Partial<{
    url: string;
    headers: Record<string, string>;
    resourceType: string;
    text: string;
}> = {}) => {
    const defaults = {
        url: 'https://example.com',
        headers: {},
        resourceType: 'document',
        text: '',
    };
    const config = { ...defaults, ...overrides };

    return {
        url: () => config.url,
        allHeaders: async () => config.headers,
        text: async () => config.text,
        request: () => ({
            resourceType: () => config.resourceType,
        }),
    } as any;
};

const createMockRequest = (url: string) => ({
    url: () => url,
}) as any;

const createMockPage = (overrides: {
    evaluateResult?: unknown;
    storageData?: { source: string; key: string; value: string }[];
    paymentFields?: { selector: string; autocomplete: string | null }[];
    web3Issues?: { type: string; evidence: string }[];
    miningIndicators?: string[];
    url?: string;
} = {}) => {
    const url = overrides.url || 'https://example.com';
    let callCount = 0;

    return {
        url: () => url,
        evaluate: async (fn: Function, ...args: unknown[]) => {
            callCount++;
            // Return different results based on call order for runPageChecks
            if (overrides.storageData && callCount === 1) return overrides.storageData;
            if (overrides.paymentFields && callCount === 2) return overrides.paymentFields;
            if (overrides.web3Issues && callCount === 3) return overrides.web3Issues;
            if (overrides.miningIndicators && callCount === 4) return overrides.miningIndicators;
            if (overrides.evaluateResult !== undefined) return overrides.evaluateResult;
            return [];
        },
        $$: async () => [],
    } as any;
};

describe('FintechScanner', () => {
    let scanner: FintechScanner;

    beforeEach(() => {
        scanner = new FintechScanner();
    });

    describe('constructor', () => {
        it('should accept custom miner domains', () => {
            const custom = new FintechScanner(['custom-miner.com']);
            expect(custom).toBeDefined();
            expect(custom.name).toBe('FintechScanner');
        });
    });

    describe('IScanner interface', () => {
        it('should have correct name', () => {
            expect(scanner.name).toBe('FintechScanner');
        });

        it('should return empty results initially', () => {
            expect(scanner.getResults()).toEqual([]);
        });

        it('should clear state', () => {
            scanner.clear();
            expect(scanner.getResults()).toEqual([]);
        });
    });

    describe('Crypto-jacking detection', () => {
        it('should detect known miner domain requests', async () => {
            const request = createMockRequest('https://coinhive.com/lib/coinhive.min.js');
            await scanner.onRequest(request);

            const results = scanner.getResults();
            expect(results.length).toBe(1);
            expect(results[0].type).toBe('cryptojacking');
            expect(results[0].severity).toBe('critical');
            expect(results[0].description).toContain('coinhive.com');
        });

        it('should detect multiple miner domains', async () => {
            for (const domain of ['cryptoloot.pro', 'jsecoin.com', 'mineralt.io']) {
                await scanner.onRequest(createMockRequest(`https://${domain}/script.js`));
            }

            const results = scanner.getResults();
            expect(results.length).toBe(3);
            results.forEach(r => {
                expect(r.type).toBe('cryptojacking');
                expect(r.severity).toBe('critical');
            });
        });

        it('should detect mining pool connections', async () => {
            await scanner.onRequest(createMockRequest('wss://pool.minergate.com/ws'));

            const results = scanner.getResults();
            expect(results.length).toBe(1);
            expect(results[0].type).toBe('cryptojacking');
            expect(results[0].description).toContain('mining pool');
        });

        it('should detect custom miner domains', async () => {
            const custom = new FintechScanner(['my-evil-miner.com']);
            await custom.onRequest(createMockRequest('https://my-evil-miner.com/mine.js'));

            expect(custom.getResults().length).toBe(1);
            expect(custom.getResults()[0].type).toBe('cryptojacking');
        });

        it('should not flag legitimate requests', async () => {
            await scanner.onRequest(createMockRequest('https://example.com/app.js'));
            await scanner.onRequest(createMockRequest('https://cdn.jsdelivr.net/npm/react'));

            expect(scanner.getResults().length).toBe(0);
        });

        it('should not duplicate findings for same URL', async () => {
            const request = createMockRequest('https://coinhive.com/lib/coinhive.min.js');
            await scanner.onRequest(request);
            await scanner.onRequest(request);

            // Second call should be skipped (URL already checked)
            expect(scanner.getResults().length).toBe(1);
        });

        it('should detect mining library in script content', async () => {
            const response = createMockResponse({
                url: 'https://example.com/app.js',
                resourceType: 'script',
                text: 'var miner = new CoinHive.Anonymous("site-key"); miner.start();',
            });

            await scanner.onResponse(response);

            const results = scanner.getResults();
            expect(results.length).toBe(1);
            expect(results[0].type).toBe('cryptojacking');
            expect(results[0].description).toContain('CoinHive.Anonymous');
        });

        it('should detect WebAssembly + crypto.subtle mining patterns', async () => {
            const response = createMockResponse({
                url: 'https://example.com/worker.js',
                resourceType: 'script',
                text: 'WebAssembly.instantiate(buffer).then(() => crypto.subtle.digest("SHA-256", data))',
            });

            await scanner.onResponse(response);

            const results = scanner.getResults();
            expect(results.length).toBe(1);
            expect(results[0].type).toBe('cryptojacking');
            expect(results[0].severity).toBe('high');
        });
    });

    describe('PCI-DSS compliance', () => {
        it('should detect missing security headers', async () => {
            const response = createMockResponse({
                url: 'https://example.com/',
                resourceType: 'document',
                headers: {
                    'content-type': 'text/html',
                },
            });

            await scanner.onResponse(response);

            const results = scanner.getResults();
            const pciResults = results.filter(r => r.type === 'pci-dss');
            expect(pciResults.length).toBeGreaterThanOrEqual(5);

            const headerNames = pciResults.map(r => r.description);
            expect(headerNames.some(d => d.includes('Strict-Transport-Security'))).toBe(true);
            expect(headerNames.some(d => d.includes('Content-Security-Policy'))).toBe(true);
            expect(headerNames.some(d => d.includes('X-Frame-Options'))).toBe(true);
        });

        it('should not flag when all PCI headers are present', async () => {
            const response = createMockResponse({
                url: 'https://example.com/',
                resourceType: 'document',
                headers: {
                    'strict-transport-security': 'max-age=31536000',
                    'x-frame-options': 'DENY',
                    'content-security-policy': "default-src 'self'",
                    'x-content-type-options': 'nosniff',
                    'x-xss-protection': '1; mode=block',
                },
            });

            await scanner.onResponse(response);
            const pciResults = scanner.getResults().filter(r => r.type === 'pci-dss');
            expect(pciResults.length).toBe(0);
        });

        it('should rate HSTS as high severity', async () => {
            const response = createMockResponse({
                url: 'https://example.com/',
                resourceType: 'document',
                headers: {
                    'x-frame-options': 'DENY',
                    'content-security-policy': "default-src 'self'",
                    'x-content-type-options': 'nosniff',
                    'x-xss-protection': '1; mode=block',
                },
            });

            await scanner.onResponse(response);
            const hstsResult = scanner.getResults().find(r => r.description.includes('Strict-Transport-Security'));
            expect(hstsResult?.severity).toBe('high');
        });

        it('should not check headers on non-document responses', async () => {
            const response = createMockResponse({
                url: 'https://example.com/app.js',
                resourceType: 'script',
                headers: {},
                text: 'console.log("hello")',
            });

            await scanner.onResponse(response);
            const headerFindings = scanner.getResults().filter(r => r.description.includes('Missing PCI'));
            expect(headerFindings.length).toBe(0);
        });
    });

    describe('Wallet drainer detection', () => {
        it('should detect known drainer domains', async () => {
            await scanner.onRequest(createMockRequest('https://inferno-drainer.xyz/api'));

            const results = scanner.getResults();
            expect(results.length).toBe(1);
            expect(results[0].type).toBe('wallet-drainer');
            expect(results[0].severity).toBe('critical');
        });

        it('should detect multiple drainer domains', async () => {
            const domains = ['angel-drainer', 'pink-drainer', 'monkey-drainer'];
            for (const domain of domains) {
                await scanner.onRequest(createMockRequest(`https://${domain}.com/drain`));
            }

            const results = scanner.getResults().filter(r => r.type === 'wallet-drainer');
            expect(results.length).toBe(3);
        });
    });

    describe('onPageCreated', () => {
        it('should attach to page', () => {
            const page = createMockPage();
            scanner.onPageCreated(page);
            // Should not throw
        });

        it('should not re-attach to same page', () => {
            const page = createMockPage();
            scanner.onPageCreated(page);
            scanner.onPageCreated(page);
            // Should not throw or duplicate
        });
    });

    describe('onClose', () => {
        it('should log findings count', () => {
            scanner.onClose();
            // Should not throw
        });
    });
});
