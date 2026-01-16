/**
 * Unit Tests for ScannerRegistry (Observer Pattern)
 */

import { ScannerRegistry, IScanner } from '../../src/core/ScannerRegistry';

// Mock scanner for testing
class MockScanner implements IScanner {
  readonly name = 'MockScanner';
  public contextCreatedCalled = false;
  public pageCreatedCalled = false;
  public requestCalled = false;
  public responseCalled = false;
  public closeCalled = false;
  public results: string[] = [];

  async onContextCreated(): Promise<void> {
    this.contextCreatedCalled = true;
  }

  async onPageCreated(): Promise<void> {
    this.pageCreatedCalled = true;
  }

  async onRequest(): Promise<void> {
    this.requestCalled = true;
  }

  async onResponse(): Promise<void> {
    this.responseCalled = true;
  }

  async onClose(): Promise<void> {
    this.closeCalled = true;
  }

  getResults(): string[] {
    return this.results;
  }

  clear(): void {
    this.results = [];
  }
}

describe('ScannerRegistry', () => {
  let registry: ScannerRegistry;

  beforeEach(() => {
    registry = new ScannerRegistry();
  });

  describe('registration', () => {
    it('should register a scanner', () => {
      const scanner = new MockScanner();
      registry.register(scanner);

      expect(registry.count).toBe(1);
      expect(registry.getScannerNames()).toContain('MockScanner');
    });

    it('should not register duplicate scanners', () => {
      const scanner = new MockScanner();
      registry.register(scanner);
      registry.register(scanner);

      expect(registry.count).toBe(1);
    });

    it('should unregister a scanner', () => {
      const scanner = new MockScanner();
      registry.register(scanner);
      registry.unregister('MockScanner');

      expect(registry.count).toBe(0);
      expect(registry.getScannerNames()).not.toContain('MockScanner');
    });

    it('should get a registered scanner by name', () => {
      const scanner = new MockScanner();
      registry.register(scanner);

      expect(registry.getScanner('MockScanner')).toBe(scanner);
    });

    it('should return undefined for unregistered scanner', () => {
      expect(registry.getScanner('NonExistent')).toBeUndefined();
    });
  });

  describe('lifecycle dispatching', () => {
    it('should dispatch onContextCreated to all scanners', async () => {
      const scanner1 = new MockScanner();
      const scanner2 = new MockScanner();
      (scanner2 as any).name = 'MockScanner2';

      registry.register(scanner1);
      registry.register(scanner2);

      await registry.dispatchContextCreated({} as any);

      expect(scanner1.contextCreatedCalled).toBe(true);
      expect(scanner2.contextCreatedCalled).toBe(true);
    });

    it('should dispatch onPageCreated to all scanners', async () => {
      const scanner = new MockScanner();
      registry.register(scanner);

      // Mock page with .on() method for event handlers
      const mockPage = {
        on: jest.fn()
      };

      await registry.dispatchPageCreated(mockPage as any);

      expect(scanner.pageCreatedCalled).toBe(true);
      // Verify event handlers were attached
      expect(mockPage.on).toHaveBeenCalledWith('request', expect.any(Function));
      expect(mockPage.on).toHaveBeenCalledWith('response', expect.any(Function));
    });

    it('should dispatch onClose to all scanners', async () => {
      const scanner = new MockScanner();
      registry.register(scanner);

      await registry.dispatchClose();

      expect(scanner.closeCalled).toBe(true);
    });
  });

  describe('result retrieval', () => {
    it('should get results from scanner via getScanner', () => {
      const scanner = new MockScanner();
      scanner.results = ['result1', 'result2'];
      registry.register(scanner);

      // Use getScanner to retrieve and then call getResults
      const retrievedScanner = registry.getScanner<MockScanner>('MockScanner');
      const results = retrievedScanner?.getResults();

      expect(results).toEqual(['result1', 'result2']);
    });

    it('should return undefined for scanner without getResults', () => {
      const minimalScanner: IScanner = { name: 'MinimalScanner' };
      registry.register(minimalScanner);

      // getScanner returns the scanner but it has no getResults method
      const retrievedScanner = registry.getScanner('MinimalScanner');
      const results = retrievedScanner?.getResults?.();

      expect(results).toBeUndefined();
    });
  });

  describe('clear all scanners', () => {
    it('should clear results from all scanners', () => {
      const scanner = new MockScanner();
      scanner.results = ['data'];
      registry.register(scanner);

      registry.clearAll();

      expect(scanner.results).toEqual([]);
    });
  });
});
