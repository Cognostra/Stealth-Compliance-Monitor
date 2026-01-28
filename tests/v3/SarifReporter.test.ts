/**
 * SARIF Reporter Unit Tests
 */

import { SarifReporter, type LscmFinding, type ScanMetadata } from '../../src/v3/reporters/SarifReporter.js';

describe('SarifReporter', () => {
    const mockMetadata: ScanMetadata = {
        targetUrl: 'https://example.com',
        startTime: '2024-01-15T10:00:00Z',
        endTime: '2024-01-15T10:05:00Z',
        version: '3.0.0',
        profile: 'standard',
    };

    const mockFindings: LscmFinding[] = [
        {
            id: 'finding-1',
            type: 'xss',
            title: 'Cross-Site Scripting (XSS)',
            description: 'Reflected XSS vulnerability found in search parameter',
            severity: 'high',
            url: 'https://example.com/search?q=test',
            selector: 'input#search',
            solution: 'Sanitize user input before rendering',
            category: 'security',
            cweId: '79',
        },
        {
            id: 'finding-2',
            type: 'missing-hsts',
            title: 'Missing HSTS Header',
            description: 'Strict-Transport-Security header is not set',
            severity: 'medium',
            url: 'https://example.com',
            category: 'security',
        },
        {
            id: 'finding-3',
            type: 'info-disclosure',
            title: 'Information Disclosure',
            description: 'Server version exposed in headers',
            severity: 'low',
            url: 'https://example.com/api',
            category: 'security',
        },
    ];

    describe('generate()', () => {
        it('should generate valid SARIF 2.1.0 structure', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
            expect(sarif.version).toBe('2.1.0');
            expect(sarif.runs).toHaveLength(1);
        });

        it('should include tool information', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const tool = sarif.runs[0].tool.driver;
            expect(tool.name).toBe('Stealth Compliance Monitor');
            expect(tool.version).toBe('3.0.0');
            expect(tool.informationUri).toContain('github.com');
        });

        it('should create rules for unique finding types', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const rules = sarif.runs[0].tool.driver.rules || [];
            expect(rules).toHaveLength(3);
            expect(rules.map((r) => r.id)).toContain('lscm/xss');
            expect(rules.map((r) => r.id)).toContain('lscm/missing-hsts');
            expect(rules.map((r) => r.id)).toContain('lscm/info-disclosure');
        });

        it('should create results for each finding', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const results = sarif.runs[0].results;
            expect(results).toHaveLength(3);
        });

        it('should map severity to SARIF level correctly', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const results = sarif.runs[0].results;
            const xssResult = results.find((r) => r.ruleId === 'lscm/xss');
            const hstsResult = results.find((r) => r.ruleId === 'lscm/missing-hsts');
            const infoResult = results.find((r) => r.ruleId === 'lscm/info-disclosure');

            expect(xssResult?.level).toBe('error'); // high → error
            expect(hstsResult?.level).toBe('warning'); // medium → warning
            expect(infoResult?.level).toBe('note'); // low → note
        });

        it('should include security-severity in properties', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const results = sarif.runs[0].results;
            const xssResult = results.find((r) => r.ruleId === 'lscm/xss');

            expect(xssResult?.properties?.['security-severity']).toBe('7.0');
        });

        it('should convert URL to artifact URI', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const results = sarif.runs[0].results;
            const xssResult = results.find((r) => r.ruleId === 'lscm/xss');
            const location = xssResult?.locations?.[0]?.physicalLocation?.artifactLocation;

            expect(location?.uri).toBe('example.com/search');
        });

        it('should include fingerprints by default', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const results = sarif.runs[0].results;
            expect(results[0].fingerprints).toBeDefined();
            expect(results[0].fingerprints?.['lscm/v1']).toBeDefined();
        });

        it('should include invocation metadata', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);

            const invocations = sarif.runs[0].invocations;
            expect(invocations).toHaveLength(1);
            expect(invocations?.[0].executionSuccessful).toBe(true);
            expect(invocations?.[0].startTimeUtc).toBe(mockMetadata.startTime);
            expect(invocations?.[0].endTimeUtc).toBe(mockMetadata.endTime);
        });
    });

    describe('toJson()', () => {
        it('should serialize SARIF to JSON string', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);
            const json = SarifReporter.toJson(sarif);

            expect(typeof json).toBe('string');
            expect(() => JSON.parse(json)).not.toThrow();
        });

        it('should format with indentation when pretty=true', () => {
            const reporter = new SarifReporter();
            const sarif = reporter.generate(mockFindings, mockMetadata);
            const prettyJson = SarifReporter.toJson(sarif, true);
            const compactJson = SarifReporter.toJson(sarif, false);

            expect(prettyJson.length).toBeGreaterThan(compactJson.length);
            expect(prettyJson).toContain('\n');
        });
    });

    describe('URL to artifact conversion', () => {
        it('should handle root URL', () => {
            const reporter = new SarifReporter();
            const findings: LscmFinding[] = [
                {
                    id: 'test',
                    type: 'test',
                    title: 'Test',
                    description: 'Test',
                    severity: 'low',
                    url: 'https://example.com/',
                },
            ];

            const sarif = reporter.generate(findings, mockMetadata);
            const uri = sarif.runs[0].results[0].locations?.[0]?.physicalLocation?.artifactLocation?.uri;
            expect(uri).toBe('example.com/index.html');
        });

        it('should preserve file extension in path', () => {
            const reporter = new SarifReporter();
            const findings: LscmFinding[] = [
                {
                    id: 'test',
                    type: 'test',
                    title: 'Test',
                    description: 'Test',
                    severity: 'low',
                    url: 'https://example.com/script.js',
                },
            ];

            const sarif = reporter.generate(findings, mockMetadata);
            const uri = sarif.runs[0].results[0].locations?.[0]?.physicalLocation?.artifactLocation?.uri;
            expect(uri).toBe('example.com/script.js');
        });
    });
});
