/**
 * Security Tests for PolicyEngine
 *
 * Tests protection against:
 * - ReDoS (Regular Expression Denial of Service)
 * - Path Traversal attacks
 * - YAML Bomb attacks
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PolicyEngine } from '../../../src/v3/core/PolicyEngine.js';
import type { PolicyEvaluationContext } from '../../../src/v3/types/policy.js';

describe('PolicyEngine Security Tests', () => {
    let engine: PolicyEngine;
    let tempDir: string;

    beforeEach(() => {
        engine = new PolicyEngine();
        // Create temporary directory for test files
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-test-'));
    });

    afterEach(() => {
        // Clean up temporary files
        if (fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });

    describe('ReDoS Protection', () => {
        it('should reject regex with nested quantifiers (a+)+', () => {
            const policy = `
policies:
  - name: Dangerous ReDoS Pattern
    condition: title matches "(a+)+"
    action: fail
`;
            expect(() => engine.loadFromString(policy)).not.toThrow();

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'aaaaaa' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            // Should throw when evaluating because regex is unsafe
            expect(() => engine.evaluate(context)).toThrow(/Unsafe regex/);
        });

        it('should reject regex with multiple wildcards .*.*', () => {
            const policy = `
policies:
  - name: Wildcard Attack
    condition: title matches ".*.*"
    action: fail
`;
            expect(() => engine.loadFromString(policy)).not.toThrow();

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'test' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            expect(() => engine.evaluate(context)).toThrow(/Unsafe regex/);
        });

        it('should reject regex exceeding maximum length', () => {
            const longPattern = 'a'.repeat(250);
            const policy = `
policies:
  - name: Too Long Pattern
    condition: title matches "${longPattern}"
    action: fail
`;
            expect(() => engine.loadFromString(policy)).not.toThrow();

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'test' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            expect(() => engine.evaluate(context)).toThrow(/maximum length/);
        });

        it('should allow safe regex patterns', () => {
            const policy = `
policies:
  - name: Safe Pattern
    condition: title matches "^[A-Za-z0-9]+$"
    action: fail
`;
            engine.loadFromString(policy);

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'abc123' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            // Should not throw for safe patterns
            expect(() => engine.evaluate(context)).not.toThrow();
        });

        it('should reject regex with alternation quantifiers', () => {
            const policy = `
policies:
  - name: Alternation Attack
    condition: title matches "(a|b|c)++"
    action: fail
`;
            expect(() => engine.loadFromString(policy)).not.toThrow();

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'abc' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            expect(() => engine.evaluate(context)).toThrow(/Unsafe regex/);
        });
    });

    describe('Path Traversal Protection', () => {
        it('should reject path traversal with ../..', () => {
            const maliciousPath = '../../etc/passwd';

            expect(() => engine.loadFromFile(maliciousPath)).toThrow(/blocked segment/);
        });

        it('should reject path to node_modules', () => {
            const maliciousPath = './node_modules/malicious.yml';

            expect(() => engine.loadFromFile(maliciousPath)).toThrow(/blocked segment/);
        });

        it('should reject path to .env file', () => {
            const maliciousPath = './.env';

            expect(() => engine.loadFromFile(maliciousPath)).toThrow(/blocked segment/);
        });

        it('should reject path to .git directory', () => {
            const maliciousPath = './.git/config';

            expect(() => engine.loadFromFile(maliciousPath)).toThrow(/blocked segment/);
        });

        it('should reject paths outside allowed directories', () => {
            // Set allowed directories to only tempDir
            const allowedDirs = [tempDir];

            // Try to load from /etc/passwd
            expect(() => engine.loadFromFile('/etc/passwd', allowedDirs)).toThrow(/within allowed directories/);
        });

        it('should reject files without .yml or .yaml extension', () => {
            const txtFile = path.join(tempDir, 'policy.txt');
            fs.writeFileSync(txtFile, 'test');

            expect(() => engine.loadFromFile(txtFile)).toThrow(/must have one of these extensions/);
        });

        it('should accept valid paths in allowed directories', () => {
            const validPath = path.join(tempDir, 'valid-policy.yml');
            const validPolicy = `
policies:
  - name: Valid Policy
    condition: severity == "high"
    action: fail
`;
            fs.writeFileSync(validPath, validPolicy);

            expect(() => engine.loadFromFile(validPath, [tempDir])).not.toThrow();
        });

        it('should normalize and accept relative paths in current directory', () => {
            const validPath = path.join(tempDir, 'test.yml');
            const validPolicy = `
policies:
  - name: Test Policy
    condition: severity == "high"
    action: fail
`;
            fs.writeFileSync(validPath, validPolicy);

            // Should work with current directory in allowed list
            expect(() => engine.loadFromFile(validPath, ['.', tempDir])).not.toThrow();
        });
    });

    describe('YAML Bomb Protection', () => {
        it('should reject YAML with excessive aliases (billion laughs)', () => {
            const yamlBomb = `
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
policies:
  - name: Bomb
    condition: severity == "high"
    action: fail
`;
            expect(() => engine.loadFromString(yamlBomb)).toThrow(/Excessive YAML aliases/);
        });

        it('should reject YAML with repeated alias pattern', () => {
            const repeatedAliases = `
a: &ref1 value
b: &ref2 value
policies:
  - name: Repeated Pattern
    items: [*ref1, *ref1, *ref1, *ref1, *ref1, *ref1, *ref1, *ref1, *ref1, *ref1, *ref1]
    condition: severity == "high"
    action: fail
`;
            expect(() => engine.loadFromString(repeatedAliases)).toThrow(/Repeated alias pattern/);
        });

        it('should reject YAML exceeding size limit', () => {
            // Create YAML larger than 1MB
            const largeValue = 'x'.repeat(500000);
            const largeYaml = `
policies:
  - name: Large Policy 1
    description: "${largeValue}"
    condition: severity == "high"
    action: fail
  - name: Large Policy 2
    description: "${largeValue}"
    condition: severity == "high"
    action: fail
  - name: Large Policy 3
    description: "${largeValue}"
    condition: severity == "high"
    action: fail
`;
            expect(() => engine.loadFromString(largeYaml)).toThrow(/exceeds maximum size/);
        });

        it('should reject YAML with too many policies (>100)', () => {
            let manyPolicies = 'policies:\n';
            for (let i = 0; i < 150; i++) {
                manyPolicies += `  - name: Policy ${i}\n    condition: severity == "high"\n    action: fail\n`;
            }

            expect(() => engine.loadFromString(manyPolicies)).toThrow(/Too many policies/);
        });

        it('should accept YAML with reasonable number of aliases', () => {
            const safeYaml = `
defaults: &defaults
  severity: high

policies:
  - name: Policy 1
    <<: *defaults
    condition: type == "xss"
    action: fail
  - name: Policy 2
    <<: *defaults
    condition: type == "sqli"
    action: fail
`;
            expect(() => engine.loadFromString(safeYaml)).not.toThrow();
        });

        it('should accept YAML within size limits', () => {
            const safeYaml = `
policies:
  - name: Safe Policy
    description: This is a reasonable description
    condition: severity == "critical" AND type == "rce"
    action: fail
  - name: Another Policy
    description: Another reasonable policy
    condition: severity == "high"
    action: warn
`;
            expect(() => engine.loadFromString(safeYaml)).not.toThrow();
        });
    });

    describe('Integration: Combined Security Tests', () => {
        it('should handle safe policy file end-to-end', () => {
            const safePolicyPath = path.join(tempDir, 'safe-policy.yml');
            const safePolicy = `
policies:
  - name: No Critical Vulnerabilities
    condition: severity == "critical"
    action: fail
  - name: No XSS
    condition: type == "xss"
    action: fail
  - name: Title Pattern
    condition: title matches "^SQL.*"
    action: warn
`;
            fs.writeFileSync(safePolicyPath, safePolicy);

            // Load the policy
            expect(() => engine.loadFromFile(safePolicyPath, [tempDir])).not.toThrow();

            // Evaluate against context
            const context: PolicyEvaluationContext = {
                findings: [
                    { id: '1', type: 'xss', severity: 'high', title: 'XSS Found' },
                    { id: '2', type: 'sqli', severity: 'critical', title: 'SQL Injection' },
                ],
                meta: {
                    targetUrl: 'https://example.com',
                    scanProfile: 'standard',
                    duration: 1000,
                    timestamp: new Date().toISOString(),
                },
            };

            const result = engine.evaluate(context);

            // Should fail because of XSS and critical severity
            expect(result.passed).toBe(false);
            expect(result.failedPolicies.length).toBeGreaterThan(0);
        });

        it('should reject malicious policy file combining multiple attacks', () => {
            const maliciousPolicyPath = path.join(tempDir, '../../../etc/passwd.yml');

            // Path traversal attempt
            expect(() => engine.loadFromFile(maliciousPolicyPath)).toThrow();
        });

        it('should maintain performance with valid complex policies', () => {
            const complexPolicy = `
policies:
  - name: Complex Condition 1
    condition: severity == "critical" AND (type == "xss" OR type == "sqli")
    action: fail
  - name: Complex Condition 2
    condition: severity == "high" AND title matches "^(SQL|XSS|RCE).*"
    action: warn
  - name: Performance Check
    condition: severity == "medium" AND NOT (type == "info-disclosure")
    action: info
`;
            const start = Date.now();
            engine.loadFromString(complexPolicy);

            const context: PolicyEvaluationContext = {
                findings: [
                    { id: '1', type: 'xss', severity: 'critical', title: 'XSS Attack' },
                    { id: '2', type: 'sqli', severity: 'high', title: 'SQL Injection' },
                    { id: '3', type: 'csrf', severity: 'medium', title: 'CSRF Token Missing' },
                ],
                meta: {
                    targetUrl: 'https://example.com',
                    scanProfile: 'standard',
                    duration: 1000,
                    timestamp: new Date().toISOString(),
                },
            };

            engine.evaluate(context);
            const duration = Date.now() - start;

            // Should complete in reasonable time (< 100ms for this simple case)
            expect(duration).toBeLessThan(100);
        });
    });

    describe('Edge Cases and Error Handling', () => {
        it('should handle empty policy file', () => {
            const emptyPath = path.join(tempDir, 'empty.yml');
            fs.writeFileSync(emptyPath, '');

            expect(() => engine.loadFromFile(emptyPath, [tempDir])).toThrow();
        });

        it('should handle malformed YAML', () => {
            const malformed = `
policies:
  - name: Bad Policy
    condition: severity == "high"
    action: fail
  - name: Unclosed String
    condition: title == "test
    action: fail
`;
            expect(() => engine.loadFromString(malformed)).toThrow();
        });

        it('should handle non-existent file', () => {
            const nonExistent = path.join(tempDir, 'does-not-exist.yml');

            expect(() => engine.loadFromFile(nonExistent, [tempDir])).toThrow(/does not exist/);
        });

        it('should validate policy structure', () => {
            const invalidStructure = `
not_policies:
  - name: Invalid
    condition: test
    action: fail
`;
            expect(() => engine.loadFromString(invalidStructure)).toThrow(/missing policies array/);
        });

        it('should handle invalid regex in safe way', () => {
            const invalidRegex = `
policies:
  - name: Invalid Regex
    condition: title matches "[unclosed"
    action: fail
`;
            engine.loadFromString(invalidRegex);

            const context: PolicyEvaluationContext = {
                findings: [{ id: '1', type: 'test', severity: 'high', title: 'test' }],
                meta: { targetUrl: 'https://example.com', scanProfile: 'test', duration: 100, timestamp: new Date().toISOString() },
            };

            // Should throw for invalid regex syntax
            expect(() => engine.evaluate(context)).toThrow();
        });
    });

    describe('Positive Security Tests (Functionality Preserved)', () => {
        it('should correctly evaluate severity-based policies', () => {
            const policy = `
policies:
  - name: Block Critical
    condition: severity == "critical"
    action: fail
  - name: Warn on High
    condition: severity == "high"
    action: warn
`;
            engine.loadFromString(policy);

            const context: PolicyEvaluationContext = {
                findings: [
                    { id: '1', type: 'rce', severity: 'critical', title: 'Remote Code Execution' },
                    { id: '2', type: 'xss', severity: 'high', title: 'Cross-Site Scripting' },
                ],
                meta: {
                    targetUrl: 'https://example.com',
                    scanProfile: 'standard',
                    duration: 1000,
                    timestamp: new Date().toISOString(),
                },
            };

            const result = engine.evaluate(context);

            expect(result.failedPolicies.length).toBe(1);
            expect(result.warnedPolicies.length).toBe(1);
            expect(result.passed).toBe(false);
        });

        it('should correctly use contains operator', () => {
            const policy = `
policies:
  - name: SQL in Title
    condition: title contains "SQL"
    action: fail
`;
            engine.loadFromString(policy);

            const context: PolicyEvaluationContext = {
                findings: [
                    { id: '1', type: 'sqli', severity: 'high', title: 'SQL Injection Found' },
                ],
                meta: {
                    targetUrl: 'https://example.com',
                    scanProfile: 'standard',
                    duration: 1000,
                    timestamp: new Date().toISOString(),
                },
            };

            const result = engine.evaluate(context);

            expect(result.failedPolicies.length).toBe(1);
        });

        it('should correctly use logical operators', () => {
            const policy = `
policies:
  - name: Critical or High XSS
    condition: (severity == "critical" OR severity == "high") AND type == "xss"
    action: fail
`;
            engine.loadFromString(policy);

            const context: PolicyEvaluationContext = {
                findings: [
                    { id: '1', type: 'xss', severity: 'high', title: 'XSS' },
                    { id: '2', type: 'sqli', severity: 'high', title: 'SQLi' },
                    { id: '3', type: 'xss', severity: 'low', title: 'Minor XSS' },
                ],
                meta: {
                    targetUrl: 'https://example.com',
                    scanProfile: 'standard',
                    duration: 1000,
                    timestamp: new Date().toISOString(),
                },
            };

            const result = engine.evaluate(context);

            // Should only match the high severity XSS
            expect(result.failedPolicies[0].matchedFindings.length).toBe(1);
            expect(result.failedPolicies[0].matchedFindings[0].id).toBe('1');
        });
    });
});
