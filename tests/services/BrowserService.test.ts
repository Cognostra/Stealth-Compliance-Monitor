/**
 * Unit Tests for BrowserService
 *
 * Note: Full integration tests require Playwright browsers installed.
 * These tests focus on initialization logic and error handling.
 */

import { BrowserService } from '../../src/services/BrowserService';
import { ScannerRegistry } from '../../src/core/ScannerRegistry';

describe('BrowserService', () => {
  let browserService: BrowserService;

  beforeEach(() => {
    browserService = new BrowserService();
  });

  afterEach(async () => {
    await browserService.close();
  });

  describe('constructor', () => {
    it('should create instance with default registry', () => {
      expect(browserService).toBeInstanceOf(BrowserService);
      expect(browserService.getRegistry()).toBeInstanceOf(ScannerRegistry);
    });

    it('should accept custom scanner registry', () => {
      const customRegistry = new ScannerRegistry();
      const service = new BrowserService(customRegistry);

      expect(service.getRegistry()).toBe(customRegistry);

      // Clean up
      service.close();
    });
  });

  describe('isReady', () => {
    it('should return false before initialization', () => {
      expect(browserService.isReady()).toBe(false);
    });
  });

  describe('ensureInitialized (via public methods)', () => {
    it('should throw error if used before initialization', async () => {
      await expect(browserService.goto('https://example.com'))
        .rejects.toThrow('BrowserService not initialized');
    });

    it('should throw error for click before initialization', async () => {
      await expect(browserService.click('button'))
        .rejects.toThrow('BrowserService not initialized');
    });

    it('should throw error for fill before initialization', async () => {
      await expect(browserService.fill('input', 'text'))
        .rejects.toThrow('BrowserService not initialized');
    });
  });

  describe('getters before initialization', () => {
    it('getPage should return null', () => {
      expect(browserService.getPage()).toBeNull();
    });

    it('getContext should return null', () => {
      expect(browserService.getContext()).toBeNull();
    });

    it('getLastResponseHeaders should return empty map', () => {
      expect(browserService.getLastResponseHeaders().size).toBe(0);
    });

    it('getNetworkIncidents should return empty array', () => {
      expect(browserService.getNetworkIncidents()).toEqual([]);
    });

    it('getLeakedSecrets should return empty array', () => {
      expect(browserService.getLeakedSecrets()).toEqual([]);
    });

    it('getConsoleErrors should return empty array', () => {
      expect(browserService.getConsoleErrors()).toEqual([]);
    });

    it('getVulnerableLibraries should return empty array', () => {
      expect(browserService.getVulnerableLibraries()).toEqual([]);
    });
  });

  describe('delay configuration', () => {
    it('should return configured min delay', () => {
      expect(browserService.getMinDelay()).toBe(100);
    });

    it('should return configured max delay', () => {
      expect(browserService.getMaxDelay()).toBe(200);
    });
  });

  describe('static closeAll', () => {
    it('should handle closing when no instances exist', async () => {
      // This should not throw
      await expect(BrowserService.closeAll()).resolves.toBeUndefined();
    });
  });
});

describe('BrowserService Integration', () => {
  let browserService: BrowserService;

  // Skip integration tests if running in CI without browsers
  const skipIntegration = process.env.CI === 'true' && !process.env.PLAYWRIGHT_BROWSERS_INSTALLED;

  beforeEach(() => {
    browserService = new BrowserService();
  });

  afterEach(async () => {
    await browserService.close();
  });

  (skipIntegration ? it.skip : it)('should initialize browser successfully', async () => {
    await browserService.initialize({ headless: true, useProxy: false });

    expect(browserService.isReady()).toBe(true);
    expect(browserService.getPage()).not.toBeNull();
    expect(browserService.getContext()).not.toBeNull();
  }, 60000);

  (skipIntegration ? it.skip : it)('should navigate to a URL', async () => {
    await browserService.initialize({ headless: true, useProxy: false });

    const result = await browserService.goto('https://example.com');

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.url).toContain('example.com');
    expect(result.timing.duration).toBeGreaterThan(0);
  }, 60000);

  (skipIntegration ? it.skip : it)('should take screenshots', async () => {
    await browserService.initialize({ headless: true, useProxy: false });
    await browserService.goto('https://example.com');

    const result = await browserService.screenshot('test-screenshot');

    expect(result.path).toContain('test-screenshot');
    expect(result.timestamp).toBeGreaterThan(0);
  }, 60000);
});
