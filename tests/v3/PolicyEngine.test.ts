/**
 * Policy Engine Unit Tests
 */

import { PolicyEngine } from '../../src/v3/core/PolicyEngine.js';
import type { Policy, PolicyEvaluationContext, PolicyMatchedFinding } from '../../src/v3/types/policy.js';

describe('PolicyEngine', () => {
    describe('loadFromString()', () => {
        it('should load valid YAML policy config', () => {
            const engine = new PolicyEngine();
            const yaml = `
policies:
  - name: "No critical vulnerabilities"
    condition: "severity == 'critical'"
    action: fail
`;
            engine.loadFromString(yaml);
            expect(engine.getPolicies()).toHaveLength(1);
        });

        it('should filter out disabled policies', () => {
            const engine = new PolicyEngine();
            const yaml = `
policies:
  - name: "Active policy"
    condition: "severity == 'high'"
    action: fail
  - name: "Disabled policy"
    condition: "severity == 'medium'"
    action: warn
    enabled: false
`;
            engine.loadFromString(yaml);
            expect(engine.getPolicies()).toHaveLength(1);
            expect(engine.getPolicies()[0].name).toBe('Active policy');
        });

        it('should throw on invalid config', () => {
            const engine = new PolicyEngine();
            expect(() => engine.loadFromString('invalid: yaml: here')).toThrow();
        });
    });

    describe('loadPolicies()', () => {
        it('should load policies from array', () => {
            const engine = new PolicyEngine();
            const policies: Policy[] = [
                { name: 'Test', condition: 'severity == "high"', action: 'fail' },
            ];
            engine.loadPolicies(policies);
            expect(engine.getPolicies()).toHaveLength(1);
        });
    });

    describe('evaluate()', () => {
        const mockContext: PolicyEvaluationContext = {
            findings: [
                { id: '1', type: 'xss', severity: 'high', title: 'XSS Found' },
                { id: '2', type: 'sqli', severity: 'critical', title: 'SQL Injection' },
                { id: '3', type: 'info-leak', severity: 'low', title: 'Info Disclosure' },
            ],
            meta: {
                targetUrl: 'https://example.com',
                scanProfile: 'standard',
                duration: 5000,
                timestamp: new Date().toISOString(),
            },
            lighthouse: {
                performance: 85,
                accessibility: 90,
                seo: 75,
                bestPractices: 80,
            },
            security: {
                critical: 1,
                high: 1,
                medium: 0,
                low: 1,
                total: 3,
            },
        };

        it('should pass when no policies match', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'No ultra severity', condition: 'severity == "ultra"', action: 'fail' },
            ]);

            const result = engine.evaluate(mockContext);
            expect(result.passed).toBe(true);
            expect(result.exitCode).toBe(0);
        });

        it('should fail when fail-action policy matches', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'No critical', condition: 'severity == "critical"', action: 'fail' },
            ]);

            const result = engine.evaluate(mockContext);
            expect(result.passed).toBe(false);
            expect(result.exitCode).toBe(1);
            expect(result.failedPolicies).toHaveLength(1);
        });

        it('should pass with warnings when warn-action policy matches', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Warn on high', condition: 'severity == "high"', action: 'warn' },
            ]);

            const result = engine.evaluate(mockContext);
            expect(result.passed).toBe(true); // warn doesn't cause failure
            expect(result.warnedPolicies).toHaveLength(1);
            expect(result.exitCode).toBe(0);
        });

        it('should include matched findings in result', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'No critical', condition: 'severity == "critical"', action: 'fail' },
            ]);

            const result = engine.evaluate(mockContext);
            const matchedFindings = result.failedPolicies[0].matchedFindings;
            expect(matchedFindings).toHaveLength(1);
            expect(matchedFindings[0].type).toBe('sqli');
        });

        it('should provide correct summary counts', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'P1', condition: 'severity == "critical"', action: 'fail' },
                { name: 'P2', condition: 'severity == "high"', action: 'warn' },
                { name: 'P3', condition: 'severity == "ultra"', action: 'fail' },
            ]);

            const result = engine.evaluate(mockContext);
            expect(result.summary.fail).toBe(1);
            expect(result.summary.warn).toBe(1);
            expect(result.summary.pass).toBe(1);
        });
    });

    describe('condition parsing', () => {
        const simpleContext: PolicyEvaluationContext = {
            findings: [
                { id: '1', type: 'test', severity: 'high', title: 'Test XSS', url: 'https://example.com/admin' },
            ],
            meta: {
                targetUrl: 'https://example.com',
                scanProfile: 'standard',
                duration: 1000,
                timestamp: new Date().toISOString(),
            },
        };

        it('should handle == operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'severity == "high"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle != operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'severity != "low"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle contains operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'title contains "XSS"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle startswith operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'title startswith "Test"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle AND logical operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'severity == "high" AND type == "test"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle OR logical operator', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: 'severity == "critical" OR severity == "high"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });

        it('should handle parentheses', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Test', condition: '(severity == "high" OR severity == "critical") AND type == "test"', action: 'fail' },
            ]);
            expect(engine.evaluate(simpleContext).passed).toBe(false);
        });
    });

    describe('context-level conditions', () => {
        const contextWithScores: PolicyEvaluationContext = {
            findings: [],
            meta: {
                targetUrl: 'https://example.com',
                scanProfile: 'standard',
                duration: 1000,
                timestamp: new Date().toISOString(),
            },
            lighthouse: {
                performance: 60,
                accessibility: 90,
                seo: 80,
                bestPractices: 85,
            },
            security: {
                critical: 2,
                high: 3,
                medium: 5,
                low: 10,
                total: 20,
            },
        };

        it('should evaluate lighthouse performance thresholds', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'Perf budget', condition: 'lighthouse_performance < 80', action: 'fail' },
            ]);
            expect(engine.evaluate(contextWithScores).passed).toBe(false);
        });

        it('should evaluate security counts', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'No criticals', condition: 'security_critical > 0', action: 'fail' },
            ]);
            expect(engine.evaluate(contextWithScores).passed).toBe(false);
        });

        it('should pass when threshold not exceeded', () => {
            const engine = new PolicyEngine();
            engine.loadPolicies([
                { name: 'A11y budget', condition: 'lighthouse_accessibility < 80', action: 'fail' },
            ]);
            expect(engine.evaluate(contextWithScores).passed).toBe(true);
        });
    });
});
