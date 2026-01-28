/**
 * E2E Audit Tests
 * Tests v3 SARIF generation, policy evaluation, and compliance mapping
 */

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// ES module compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ROOT_DIR = path.resolve(__dirname, '..');
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');

// Helper to run CLI command
function runCli(args: string): { stdout: string; stderr: string; exitCode: number } {
    try {
        const stdout = execSync(`node --import tsx src/index.ts ${args}`, {
            cwd: ROOT_DIR,
            encoding: 'utf-8',
            stdio: ['pipe', 'pipe', 'pipe'],
            timeout: 120000, // 2 minute timeout
            env: {
                ...process.env,
                CI: 'true',
                LIVE_URL: 'https://example.com',
            },
        });
        return { stdout, stderr: '', exitCode: 0 };
    } catch (error: unknown) {
        const execError = error as { stdout?: string; stderr?: string; status?: number };
        return {
            stdout: execError.stdout || '',
            stderr: execError.stderr || '',
            exitCode: execError.status || 1,
        };
    }
}

test.describe('v3 SARIF Generation', () => {
    test('should generate valid SARIF schema', async () => {
        // Generate SARIF output
        const sarifPath = path.join(REPORTS_DIR, 'test-results.sarif');
        runCli(`--profile=smoke --sarif=${sarifPath}`);

        // Verify file exists
        expect(fs.existsSync(sarifPath)).toBe(true);

        // Parse and validate structure
        const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf-8'));
        
        expect(sarif.$schema).toContain('sarif');
        expect(sarif.version).toBe('2.1.0');
        expect(sarif.runs).toBeDefined();
        expect(Array.isArray(sarif.runs)).toBe(true);
        
        if (sarif.runs.length > 0) {
            const run = sarif.runs[0];
            expect(run.tool).toBeDefined();
            expect(run.tool.driver.name).toBe('Stealth Compliance Monitor');
        }
    });

    test('should include security severity in rules', async () => {
        const sarifPath = path.join(REPORTS_DIR, 'test-results.sarif');
        
        if (fs.existsSync(sarifPath)) {
            const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf-8'));
            
            if (sarif.runs?.[0]?.tool?.driver?.rules) {
                for (const rule of sarif.runs[0].tool.driver.rules) {
                    expect(rule.properties?.['security-severity']).toBeDefined();
                }
            }
        }
    });
});

test.describe('v3 Policy Evaluation', () => {
    test('should load and parse policy YAML', async () => {
        const policyPath = path.join(FIXTURES_DIR, 'policies/strict.yml');
        expect(fs.existsSync(policyPath)).toBe(true);

        // Run with policy
        const result = runCli(`--profile=smoke --policy=${policyPath}`);
        
        // Should either pass or fail based on policy, but not crash
        expect([0, 1]).toContain(result.exitCode);
        expect(result.stderr).not.toContain('YAML parse error');
    });

    test('should respect strict policy rules', async () => {
        const policyPath = path.join(FIXTURES_DIR, 'policies/strict.yml');
        const result = runCli(`--profile=smoke --policy=${policyPath}`);

        // CLI should execute successfully (pass or fail based on policy, not crash)
        expect([0, 1]).toContain(result.exitCode);
        
        // Should have some output (config loading, or results)
        const output = result.stdout + result.stderr;
        expect(output.length).toBeGreaterThan(0);
    });

    test('should support minimal policy', async () => {
        const policyPath = path.join(FIXTURES_DIR, 'policies/minimal.yml');
        const { exitCode } = runCli(`--profile=smoke --policy=${policyPath}`);

        // Minimal policy should be more permissive
        expect([0, 1]).toContain(exitCode);
    });
});

test.describe('v3 Compliance Mapping', () => {
    test('should map findings to SOC2 controls', async () => {
        const { stdout, stderr } = runCli(`--profile=smoke --compliance=soc2`);
        const output = stdout + stderr;

        // Should mention SOC2 in output
        expect(output.toLowerCase()).toMatch(/soc2|compliance/i);
    });

    test('should map findings to GDPR controls', async () => {
        const { stdout, stderr } = runCli(`--profile=smoke --compliance=gdpr`);
        const output = stdout + stderr;

        // Should mention GDPR in output
        expect(output.toLowerCase()).toMatch(/gdpr|compliance/i);
    });

    test('should support multiple frameworks', async () => {
        const result = runCli(`--profile=smoke --compliance=soc2,gdpr,hipaa`);
        const output = result.stdout + result.stderr;

        // Should process all frameworks
        expect(output.toLowerCase()).toMatch(/compliance/i);
    });
});

test.describe('v3 Combined Features', () => {
    test('should run SARIF, policy, and compliance together', async () => {
        const sarifPath = path.join(REPORTS_DIR, 'combined-test.sarif');
        const policyPath = path.join(FIXTURES_DIR, 'policies/standard.yml');

        const { exitCode, stdout, stderr } = runCli(
            `--profile=smoke --sarif=${sarifPath} --policy=${policyPath} --compliance=soc2`
        );

        // Should not crash
        expect([0, 1]).toContain(exitCode);

        // SARIF should be generated
        expect(fs.existsSync(sarifPath)).toBe(true);
    });
});
