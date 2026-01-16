/**
 * Unit Tests for Environment Configuration
 */

import { loadEnvConfig, getConfig, resetConfig, EnvConfig } from '../../src/config/env';

describe('Environment Configuration', () => {
  beforeEach(() => {
    resetConfig();
  });

  describe('loadEnvConfig', () => {
    it('should load required environment variables', () => {
      const config = loadEnvConfig();

      expect(config.LIVE_URL).toBe('https://example.com');
      expect(config.TEST_EMAIL).toBe('test@example.com');
      expect(config.TEST_PASSWORD).toBe('test_password_123');
    });

    it('should load optional variables with defaults', () => {
      const config = loadEnvConfig();

      expect(config.ZAP_PROXY_URL).toBe('http://localhost:8080');
      expect(config.MIN_DELAY_MS).toBe(100);
      expect(config.MAX_DELAY_MS).toBe(200);
    });

    it('should throw error if required variable is missing', () => {
      const originalLiveUrl = process.env.LIVE_URL;
      delete process.env.LIVE_URL;

      expect(() => loadEnvConfig()).toThrow('[CONFIG ERROR] Missing required environment variable: LIVE_URL');

      process.env.LIVE_URL = originalLiveUrl;
    });

    it('should throw error if LIVE_URL is invalid URL', () => {
      const originalLiveUrl = process.env.LIVE_URL;
      process.env.LIVE_URL = 'not-a-valid-url';

      expect(() => loadEnvConfig()).toThrow('[CONFIG ERROR] Invalid URL format');

      process.env.LIVE_URL = originalLiveUrl;
    });

    it('should throw error if MAX_DELAY < MIN_DELAY', () => {
      const originalMin = process.env.MIN_DELAY_MS;
      const originalMax = process.env.MAX_DELAY_MS;

      process.env.MIN_DELAY_MS = '5000';
      process.env.MAX_DELAY_MS = '1000';

      expect(() => loadEnvConfig()).toThrow('MAX_DELAY_MS');

      process.env.MIN_DELAY_MS = originalMin;
      process.env.MAX_DELAY_MS = originalMax;
    });
  });

  describe('getConfig (singleton)', () => {
    it('should return the same instance on multiple calls', () => {
      const config1 = getConfig();
      const config2 = getConfig();

      expect(config1).toBe(config2);
    });

    it('should return fresh instance after reset', () => {
      const config1 = getConfig();
      resetConfig();
      const config2 = getConfig();

      // Different object references
      expect(config1).not.toBe(config2);
      // But same values
      expect(config1.LIVE_URL).toBe(config2.LIVE_URL);
    });
  });

  describe('ENABLE_AI parsing', () => {
    it('should parse ENABLE_AI as boolean', () => {
      const original = process.env.ENABLE_AI;

      process.env.ENABLE_AI = 'true';
      resetConfig();
      expect(getConfig().ENABLE_AI).toBe(true);

      process.env.ENABLE_AI = 'false';
      resetConfig();
      expect(getConfig().ENABLE_AI).toBe(false);

      process.env.ENABLE_AI = 'TRUE';
      resetConfig();
      expect(getConfig().ENABLE_AI).toBe(true);

      process.env.ENABLE_AI = original;
    });
  });
});
