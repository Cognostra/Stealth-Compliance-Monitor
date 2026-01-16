/**
 * Unit Tests for SecretScanner
 *
 * Tests the secret detection patterns for various credential types.
 */

import { SecretScanner, LeakedSecret } from '../../src/services/SecretScanner.js';

describe('SecretScanner', () => {
  let scanner: SecretScanner;

  beforeEach(() => {
    scanner = new SecretScanner();
  });

  describe('IScanner interface', () => {
    it('should have correct name', () => {
      expect(scanner.name).toBe('SecretScanner');
    });

    it('should return empty secrets initially', () => {
      expect(scanner.getSecrets()).toEqual([]);
      expect(scanner.getResults()).toEqual([]);
    });

    it('should clear secrets', () => {
      // Access private method for testing via scanContent
      const scanContent = (scanner as any).scanContent.bind(scanner);
      scanContent('https://example.com/app.js', 'const key = "AKIAIOSFODNN7EXAMPLE"');

      expect(scanner.getSecrets().length).toBeGreaterThan(0);

      scanner.clear();

      expect(scanner.getSecrets()).toEqual([]);
    });
  });

  describe('secret pattern detection', () => {
    // Helper to scan text content using private method
    const scanText = (url: string, text: string) => {
      (scanner as any).scanContent(url, text);
    };

    beforeEach(() => {
      scanner.clear();
    });

    it('should detect AWS access keys', () => {
      scanText('https://example.com/app.js', 'const key = "AKIAIOSFODNN7EXAMPLE"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('AWS Access Key');
      expect(secrets[0].risk).toBe('CRITICAL');
    });

    it('should detect GitHub tokens', () => {
      scanText('https://example.com/app.js', 'token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('GitHub Token');
      expect(secrets[0].risk).toBe('CRITICAL');
    });

    it('should detect Stripe live secret keys as CRITICAL', () => {
      // Using split string to avoid GitHub push protection false positive on test data
      const testKey = 'sk_' + 'live_' + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      scanText('https://example.com/app.js', `stripe_key = "${testKey}"`);

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Stripe Live Secret Key');
      expect(secrets[0].risk).toBe('CRITICAL');
    });

    it('should detect Stripe test keys as MEDIUM risk', () => {
      // Using split string to avoid GitHub push protection false positive on test data
      const testKey = 'sk_' + 'test_' + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      scanText('https://example.com/app.js', `stripe_key = "${testKey}"`);

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Stripe Test Secret Key');
      expect(secrets[0].risk).toBe('MEDIUM');
    });

    it('should detect Google API keys', () => {
      scanText('https://example.com/app.js', 'const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBeGreaterThanOrEqual(1);
      // Check that at least one secret is a Google API Key
      const googleApiKey = secrets.find(s => s.type === 'Google API Key');
      expect(googleApiKey).toBeDefined();
      expect(googleApiKey?.risk).toBe('HIGH');
    });

    it('should detect database connection strings', () => {
      scanText('https://example.com/app.js', 'const db = "postgres://user:password@localhost:5432/mydb"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Database Connection String');
      expect(secrets[0].risk).toBe('CRITICAL');
    });

    it('should detect Slack tokens', () => {
      scanText('https://example.com/app.js', 'const token = "xoxb-123456789-abcdefghij"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Slack Token');
      expect(secrets[0].risk).toBe('HIGH');
    });

    it('should detect SendGrid API keys', () => {
      scanText('https://example.com/app.js', 'const key = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('SendGrid API Key');
      expect(secrets[0].risk).toBe('HIGH');
    });

    it('should detect private keys', () => {
      scanText('https://example.com/app.js', '-----BEGIN RSA PRIVATE KEY-----');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Private Key (RSA/PEM)');
      expect(secrets[0].risk).toBe('CRITICAL');
    });

    it('should detect hardcoded JWTs', () => {
      scanText('https://example.com/app.js', 'token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"');

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(1);
      expect(secrets[0].type).toBe('Hardcoded JWT');
    });

    it('should detect multiple secrets in same file', () => {
      // Using split string to avoid GitHub push protection false positive on test data
      const stripeLive = 'sk_' + 'live_' + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      scanText('https://example.com/app.js', `
        const awsKey = "AKIAIOSFODNN7EXAMPLE";
        const stripeKey = "${stripeLive}";
        const ghToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
      `);

      const secrets = scanner.getSecrets();
      expect(secrets.length).toBe(3);
    });

    it('should NOT flag common false positives', () => {
      scanText('https://example.com/app.js', 'secret = "placeholder"');

      const secrets = scanner.getSecrets();
      expect(secrets).toEqual([]);
    });

    it('should handle empty content', () => {
      scanText('https://example.com/app.js', '');
      expect(scanner.getSecrets()).toEqual([]);
    });
  });

  describe('secret masking', () => {
    it('should mask secrets in output', () => {
      const scanText = (url: string, text: string) => {
        (scanner as any).scanContent(url, text);
      };

      scanText('https://example.com/app.js', 'const key = "AKIAIOSFODNN7EXAMPLE"');

      const secrets = scanner.getSecrets();
      expect(secrets[0].maskedValue).toMatch(/^AKIAIO\.\.\.MPLE$/);
    });
  });

  describe('file URL tracking', () => {
    it('should record the source file URL', () => {
      const scanText = (url: string, text: string) => {
        (scanner as any).scanContent(url, text);
      };

      const testUrl = 'https://example.com/js/bundle.min.js';
      scanText(testUrl, 'const key = "AKIAIOSFODNN7EXAMPLE"');

      const secrets = scanner.getSecrets();
      expect(secrets[0].fileUrl).toBe(testUrl);
    });
  });

  describe('safe external filtering', () => {
    it('should identify safe external domains', () => {
      const isSafeExternal = (scanner as any).isSafeExternal.bind(scanner);

      expect(isSafeExternal('https://www.google-analytics.com/analytics.js')).toBe(true);
      expect(isSafeExternal('https://www.googletagmanager.com/gtm.js')).toBe(true);
      expect(isSafeExternal('https://example.com/app.js')).toBe(false);
    });
  });
});
