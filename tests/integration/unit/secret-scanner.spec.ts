/**
 * Integration Tests: Secret Scanner
 *
 * Tests the secret detection patterns and scanning functionality.
 */

import { test, expect } from '../fixtures';
import { SecretScanner, LeakedSecret } from '../../../src/services/SecretScanner';

test.describe('Secret Scanner', () => {
    let scanner: SecretScanner;

    test.beforeEach(() => {
        scanner = new SecretScanner();
    });

    test.afterEach(() => {
        scanner.clear();
    });

    test('should have correct scanner name', async () => {
        expect(scanner.name).toBe('SecretScanner');
    });

    test('should start with empty results', async () => {
        expect(scanner.getSecrets()).toEqual([]);
        expect(scanner.getResults()).toEqual([]);
    });

    test('should detect AWS access keys', async () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('AWS Access Key');
        expect(secrets[0].risk).toBe('CRITICAL');
    });

    test('should detect GitHub tokens', async () => {
        const content = 'token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('GitHub Token');
        expect(secrets[0].risk).toBe('CRITICAL');
    });

    test('should detect Stripe live keys as CRITICAL', async () => {
        // Using split string to avoid GitHub push protection false positive on test data
        const prefix = 'sk_' + 'live_';
        const content = `const stripeKey = "${prefix}xxxxxxxxxxxxxxxxxxxxxxxxxxxx"`;
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('Stripe Live Secret Key');
        expect(secrets[0].risk).toBe('CRITICAL');
    });

    test('should detect Stripe test keys as MEDIUM', async () => {
        // Using split string to avoid GitHub push protection false positive on test data
        const prefix = 'sk_' + 'test_';
        const content = `const stripeKey = "${prefix}xxxxxxxxxxxxxxxxxxxxxxxxxxxx"`;
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('Stripe Test Secret Key');
        expect(secrets[0].risk).toBe('MEDIUM');
    });

    test('should detect Google API keys', async () => {
        const content = 'const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBeGreaterThanOrEqual(1);
        const googleKey = secrets.find(s => s.type === 'Google API Key');
        expect(googleKey).toBeDefined();
        expect(googleKey?.risk).toBe('HIGH');
    });

    test('should detect database connection strings', async () => {
        const content = 'const db = "postgres://user:password@localhost:5432/mydb"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('Database Connection String');
        expect(secrets[0].risk).toBe('CRITICAL');
    });

    test('should detect Slack tokens', async () => {
        const content = 'const token = "xoxb-123456789-abcdefghij"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('Slack Token');
        expect(secrets[0].risk).toBe('HIGH');
    });

    test('should detect private keys', async () => {
        const content = '-----BEGIN RSA PRIVATE KEY-----';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(1);
        expect(secrets[0].type).toBe('Private Key (RSA/PEM)');
        expect(secrets[0].risk).toBe('CRITICAL');
    });

    test('should detect multiple secrets in same file', async () => {
        // Using split strings to avoid GitHub push protection false positive on test data
        const stripeLive = 'sk_' + 'live_' + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
        const content = `
            const awsKey = "AKIAIOSFODNN7EXAMPLE";
            const stripeKey = "${stripeLive}";
            const ghToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        `;
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets.length).toBe(3);
    });

    test('should NOT flag common placeholders as secrets', async () => {
        const content = 'secret = "placeholder"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets).toEqual([]);
    });

    test('should mask secrets in output', async () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        const secrets = scanner.getSecrets();
        expect(secrets[0].maskedValue).toMatch(/^AKIAIO\.\.\.MPLE$/);
    });

    test('should record file URL with secret', async () => {
        const testUrl = 'https://example.com/js/bundle.min.js';
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE"';
        (scanner as any).scanContent(testUrl, content);

        const secrets = scanner.getSecrets();
        expect(secrets[0].fileUrl).toBe(testUrl);
    });

    test('should skip safe external domains', async () => {
        const isSafeExternal = (scanner as any).isSafeExternal.bind(scanner);

        expect(isSafeExternal('https://www.google-analytics.com/analytics.js')).toBe(true);
        expect(isSafeExternal('https://www.googletagmanager.com/gtm.js')).toBe(true);
        expect(isSafeExternal('https://example.com/app.js')).toBe(false);
    });

    test('should clear all results', async () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE"';
        (scanner as any).scanContent('https://example.com/app.js', content);

        expect(scanner.getSecrets().length).toBeGreaterThan(0);

        scanner.clear();

        expect(scanner.getSecrets()).toEqual([]);
    });
});
