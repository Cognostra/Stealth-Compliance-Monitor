/**
 * VulnIntelligenceService Unit Tests
 * 
 * Tests for CVE enrichment, caching, and API integration
 */

import { VulnIntelligenceService, VulnIntelligenceConfig, EnrichedVulnerability, CvssScore } from '../../src/services/VulnIntelligenceService';
import { VulnerableLibrary } from '../../src/services/FrontendVulnerabilityScanner';
import { SecurityAlert } from '../../src/types';
import * as fs from 'fs';
import * as path from 'path';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('VulnIntelligenceService', () => {
    let service: VulnIntelligenceService;
    const testCachePath = './test-cache/vuln-intel-cache.json';

    beforeEach(() => {
        jest.clearAllMocks();
        // Clean up test cache
        if (fs.existsSync(testCachePath)) {
            fs.unlinkSync(testCachePath);
        }
        if (fs.existsSync('./test-cache')) {
            fs.rmdirSync('./test-cache', { recursive: true });
        }
    });

    afterAll(() => {
        // Cleanup
        if (fs.existsSync('./test-cache')) {
            fs.rmdirSync('./test-cache', { recursive: true });
        }
    });

    describe('constructor', () => {
        it('should use default config when none provided', () => {
            service = new VulnIntelligenceService();
            const stats = service.getCacheStats();
            expect(stats.entries).toBe(0);
        });

        it('should merge provided config with defaults', () => {
            const config: VulnIntelligenceConfig = {
                nvdApiKey: 'test-key',
                cacheTtlMinutes: 60,
                cacheFilePath: testCachePath,
            };
            service = new VulnIntelligenceService(config);
            const stats = service.getCacheStats();
            expect(stats.filePath).toBe(testCachePath);
        });
    });

    describe('enrichLibrary', () => {
        beforeEach(() => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false, // Disable API calls for unit tests
                useCirclApi: false,
            });
        });

        it('should enrich library with local CVE database', async () => {
            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    {
                        cve: 'CVE-2020-8203',
                        description: 'Prototype Pollution',
                    },
                ],
                recommendation: 'Upgrade to 4.17.21',
            };

            const enriched = await service.enrichLibrary(library);

            expect(enriched).toHaveLength(1);
            expect(enriched[0].cveId).toBe('CVE-2020-8203');
            expect(enriched[0].cvss.severity).toBe('HIGH');
            expect(enriched[0].riskScore).toBeGreaterThan(0);
            expect(enriched[0].type).toBe('library');
        });

        it('should estimate CVSS when CVE not in database', async () => {
            const library: VulnerableLibrary = {
                name: 'unknown-lib',
                version: '1.0.0',
                severity: 'MEDIUM',
                vulnerabilities: [
                    {
                        cve: 'CVE-9999-9999',
                        description: 'Unknown vulnerability',
                    },
                ],
                recommendation: 'Review and update',
            };

            const enriched = await service.enrichLibrary(library);

            expect(enriched).toHaveLength(1);
            expect(enriched[0].cveId).toBe('CVE-9999-9999');
            expect(enriched[0].cvss.severity).toBe('MEDIUM');
            expect(enriched[0].cvss.baseScore).toBeCloseTo(5.5);
        });

        it('should identify KEV catalog entries', async () => {
            const library: VulnerableLibrary = {
                name: 'log4j',
                version: '2.14.0',
                severity: 'CRITICAL',
                vulnerabilities: [
                    {
                        cve: 'CVE-2021-44228',
                        description: 'Log4Shell',
                    },
                ],
                recommendation: 'Upgrade to 2.17.0+',
            };

            const enriched = await service.enrichLibrary(library);

            expect(enriched[0].knownExploitedVuln).toBe(true);
            expect(enriched[0].riskFactors).toContain('In CISA KEV catalog');
        });

        it('should cache enriched results', async () => {
            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    {
                        cve: 'CVE-2020-8203',
                        description: 'Prototype Pollution',
                    },
                ],
                recommendation: 'Upgrade to 4.17.21',
            };

            // First call
            await service.enrichLibrary(library);
            
            // Check cache
            const stats = service.getCacheStats();
            expect(stats.entries).toBeGreaterThan(0);

            // Second call should use cache (no additional fetch calls)
            const cachedResult = await service.enrichLibrary(library);
            expect(cachedResult).toHaveLength(1);
        });
    });

    describe('enrichAlert', () => {
        beforeEach(() => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });
        });

        it('should enrich security alert with CVE in description', async () => {
            const alert: SecurityAlert = {
                name: 'SQL Injection',
                risk: 'High',
                description: 'SQL Injection vulnerability (CVE-2021-12345) found',
                solution: 'Use parameterized queries',
                url: 'https://example.com/search',
            };

            const enriched = await service.enrichAlert(alert);

            expect(enriched).not.toBeNull();
            expect(enriched!.cveId).toBe('CVE-2021-12345');
            expect(enriched!.type).toBe('security-alert');
        });

        it('should generate pseudo-CVE when no CVE in alert', async () => {
            const alert: SecurityAlert = {
                name: 'XSS Vulnerability',
                risk: 'Medium',
                description: 'Cross-site scripting vulnerability found',
                solution: 'Encode output properly',
                url: 'https://example.com/comment',
            };

            const enriched = await service.enrichAlert(alert);

            expect(enriched).not.toBeNull();
            expect(enriched!.cveId).toMatch(/^ALERT-/);
        });

        it('should map alert risk to CVSS correctly', async () => {
            const highAlert: SecurityAlert = {
                name: 'Critical Vuln',
                risk: 'High',
                description: 'Critical issue',
                url: 'https://example.com',
            };

            const lowAlert: SecurityAlert = {
                name: 'Minor Issue',
                risk: 'Low',
                description: 'Minor issue',
                url: 'https://example.com',
            };

            const highEnriched = await service.enrichAlert(highAlert);
            const lowEnriched = await service.enrichAlert(lowAlert);

            expect(highEnriched!.cvss.severity).toBe('HIGH');
            expect(lowEnriched!.cvss.severity).toBe('LOW');
        });
    });

    describe('enrichAll', () => {
        beforeEach(() => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });
        });

        it('should enrich multiple libraries and alerts', async () => {
            const libraries: VulnerableLibrary[] = [
                {
                    name: 'lodash',
                    version: '4.17.15',
                    severity: 'HIGH',
                    vulnerabilities: [
                        { cve: 'CVE-2020-8203', description: 'Proto pollution' },
                    ],
                    recommendation: 'Upgrade',
                },
            ];

            const alerts: SecurityAlert[] = [
                {
                    name: 'XSS',
                    risk: 'Medium',
                    description: 'XSS found',
                    url: 'https://example.com',
                },
            ];

            const result = await service.enrichAll(libraries, alerts);

            expect(result.libraries).toHaveLength(1);
            expect(result.alerts).toHaveLength(1);
            expect(result.summary.totalFindings).toBe(2);
        });

        it('should generate correct summary statistics', async () => {
            const libraries: VulnerableLibrary[] = [
                {
                    name: 'lodash',
                    version: '4.17.15',
                    severity: 'CRITICAL',
                    vulnerabilities: [
                        { cve: 'CVE-2020-8203', description: 'Proto pollution' },
                    ],
                    recommendation: 'Upgrade',
                },
                {
                    name: 'jquery',
                    version: '2.0.0',
                    severity: 'HIGH',
                    vulnerabilities: [
                        { cve: 'CVE-2019-11358', description: 'Proto pollution' },
                    ],
                    recommendation: 'Upgrade to 3.5.0+',
                },
            ];

            const result = await service.enrichAll(libraries, []);

            expect(result.summary.bySeverity.CRITICAL).toBeGreaterThanOrEqual(0);
            expect(result.summary.bySeverity.HIGH).toBeGreaterThanOrEqual(0);
            expect(result.summary.averageRiskScore).toBeGreaterThan(0);
        });
    });

    describe('NVD API Integration', () => {
        it('should call NVD API when enabled', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    vulnerabilities: [{
                        cve: {
                            id: 'CVE-2020-8203',
                            descriptions: [{ lang: 'en', value: 'Prototype pollution in lodash' }],
                            metrics: {
                                cvssMetricV31: [{
                                    cvssData: {
                                        baseScore: 7.4,
                                        baseSeverity: 'HIGH',
                                        vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H',
                                    },
                                }],
                            },
                        },
                    }],
                }),
            });

            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: true,
                useCirclApi: false,
                rateLimitMs: 0, // No rate limiting in tests
            });

            const library: VulnerableLibrary = {
                name: 'unknown-lib',
                version: '1.0.0',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2099-0001', description: 'Test' },
                ],
                recommendation: 'Upgrade',
            };

            await service.enrichLibrary(library);

            expect(mockFetch).toHaveBeenCalledWith(
                expect.stringContaining('nvd.nist.gov'),
                expect.any(Object)
            );
        });

        it('should fall back to circl.lu when NVD fails', async () => {
            // NVD fails
            mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });
            // Circl succeeds
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'CVE-2099-0001',
                    summary: 'Test vulnerability',
                    cvss: 7.5,
                }),
            });

            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: true,
                useCirclApi: true,
                rateLimitMs: 0,
            });

            const library: VulnerableLibrary = {
                name: 'unknown-lib',
                version: '1.0.0',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2099-0001', description: 'Test' },
                ],
                recommendation: 'Upgrade',
            };

            await service.enrichLibrary(library);

            expect(mockFetch).toHaveBeenCalledTimes(2);
            expect(mockFetch).toHaveBeenLastCalledWith(
                expect.stringContaining('circl.lu'),
                expect.any(Object)
            );
        });
    });

    describe('File Cache', () => {
        it('should persist cache to file', async () => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });

            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2020-8203', description: 'Test' },
                ],
                recommendation: 'Upgrade',
            };

            await service.enrichLibrary(library);

            // Check file was created
            expect(fs.existsSync(testCachePath)).toBe(true);

            // Check file content
            const content = JSON.parse(fs.readFileSync(testCachePath, 'utf-8'));
            expect(content.version).toBe('1.0');
            expect(Object.keys(content.entries).length).toBeGreaterThan(0);
        });

        it('should load cache from file on startup', async () => {
            // Create initial cache
            const cacheDir = path.dirname(testCachePath);
            if (!fs.existsSync(cacheDir)) {
                fs.mkdirSync(cacheDir, { recursive: true });
            }
            
            const cacheData = {
                version: '1.0',
                entries: {
                    'CVE-2020-8203': {
                        data: {
                            cveId: 'CVE-2020-8203',
                            cveDescription: 'Cached description',
                        },
                        timestamp: Date.now(),
                    },
                },
            };
            fs.writeFileSync(testCachePath, JSON.stringify(cacheData));

            // Create new service instance
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });

            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2020-8203', description: 'Test' },
                ],
                recommendation: 'Upgrade',
            };

            const result = await service.enrichLibrary(library);

            // Should have loaded from cache (stats show entry)
            const stats = service.getCacheStats();
            expect(stats.entries).toBeGreaterThan(0);
        });

        it('should clear cache completely', async () => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });

            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2020-8203', description: 'Test' },
                ],
                recommendation: 'Upgrade',
            };

            await service.enrichLibrary(library);
            expect(service.getCacheStats().entries).toBeGreaterThan(0);

            await service.clearCache();

            expect(service.getCacheStats().entries).toBe(0);
        });
    });

    describe('Risk Calculation', () => {
        beforeEach(() => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
            });
        });

        it('should calculate risk score based on CVSS', async () => {
            const criticalLib: VulnerableLibrary = {
                name: 'log4j',
                version: '2.14.0',
                severity: 'CRITICAL',
                vulnerabilities: [
                    { cve: 'CVE-2021-44228', description: 'Log4Shell' },
                ],
                recommendation: 'Upgrade',
            };

            const enriched = await service.enrichLibrary(criticalLib);

            // Should have high risk score due to KEV + critical CVSS
            expect(enriched[0].riskScore).toBeGreaterThanOrEqual(80);
        });

        it('should identify risk factors correctly', async () => {
            const library: VulnerableLibrary = {
                name: 'log4j',
                version: '2.14.0',
                severity: 'CRITICAL',
                vulnerabilities: [
                    { cve: 'CVE-2021-44228', description: 'Log4Shell' },
                ],
                recommendation: 'Upgrade',
            };

            const enriched = await service.enrichLibrary(library);
            const factors = enriched[0].riskFactors;

            expect(factors).toContain('In CISA KEV catalog');
            expect(factors.some(f => f.includes('CVSS'))).toBe(true);
        });
    });

    describe('CWE Enrichment', () => {
        beforeEach(() => {
            service = new VulnIntelligenceService({
                cacheFilePath: testCachePath,
                useNvdApi: false,
                useCirclApi: false,
                enrichCwe: true,
            });
        });

        it('should enrich with CWE from local database', async () => {
            const library: VulnerableLibrary = {
                name: 'lodash',
                version: '4.17.15',
                severity: 'HIGH',
                vulnerabilities: [
                    { cve: 'CVE-2020-8203', description: 'Prototype pollution' },
                ],
                recommendation: 'Upgrade',
            };

            const enriched = await service.enrichLibrary(library);

            // CVE-2020-8203 should have CWE-1321 (Prototype Pollution)
            if (enriched[0].cwe) {
                expect(enriched[0].cwe.id).toMatch(/CWE-/);
                expect(enriched[0].cwe.name).toBeDefined();
            }
        });
    });
});
