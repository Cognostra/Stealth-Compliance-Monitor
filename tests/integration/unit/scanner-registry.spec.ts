/**
 * Integration Tests: Scanner Registry
 *
 * Tests the observer pattern implementation for scanner management.
 */

import { test, expect } from '../fixtures/index.js';
import { ScannerRegistry, IScanner } from '../../../src/core/ScannerRegistry.js';

// Mock scanner for testing
class MockScanner implements IScanner {
    readonly name: string;
    public contextCreatedCalled = false;
    public pageCreatedCalled = false;
    public closeCalled = false;
    public results: string[] = [];

    constructor(name: string = 'MockScanner') {
        this.name = name;
    }

    async onContextCreated(): Promise<void> {
        this.contextCreatedCalled = true;
    }

    async onPageCreated(): Promise<void> {
        this.pageCreatedCalled = true;
    }

    async onClose(): Promise<void> {
        this.closeCalled = true;
    }

    getResults(): string[] {
        return this.results;
    }

    clear(): void {
        this.results = [];
        this.contextCreatedCalled = false;
        this.pageCreatedCalled = false;
        this.closeCalled = false;
    }
}

test.describe('Scanner Registry', () => {
    let registry: ScannerRegistry;

    test.beforeEach(() => {
        registry = new ScannerRegistry();
    });

    test('should register scanners', async () => {
        const scanner = new MockScanner();
        registry.register(scanner);

        expect(registry.count).toBe(1);
        expect(registry.getScannerNames()).toContain('MockScanner');
    });

    test('should not register duplicate scanners', async () => {
        const scanner = new MockScanner();
        registry.register(scanner);
        registry.register(scanner);

        expect(registry.count).toBe(1);
    });

    test('should register multiple different scanners', async () => {
        const scanner1 = new MockScanner('Scanner1');
        const scanner2 = new MockScanner('Scanner2');

        registry.register(scanner1);
        registry.register(scanner2);

        expect(registry.count).toBe(2);
        expect(registry.getScannerNames()).toContain('Scanner1');
        expect(registry.getScannerNames()).toContain('Scanner2');
    });

    test('should unregister scanners by name', async () => {
        const scanner = new MockScanner();
        registry.register(scanner);

        const result = registry.unregister('MockScanner');

        expect(result).toBe(true);
        expect(registry.count).toBe(0);
    });

    test('should return false when unregistering non-existent scanner', async () => {
        const result = registry.unregister('NonExistent');
        expect(result).toBe(false);
    });

    test('should get scanner by name', async () => {
        const scanner = new MockScanner();
        registry.register(scanner);

        const retrieved = registry.getScanner<MockScanner>('MockScanner');
        expect(retrieved).toBe(scanner);
    });

    test('should dispatch close event to all scanners', async () => {
        const scanner1 = new MockScanner('Scanner1');
        const scanner2 = new MockScanner('Scanner2');

        registry.register(scanner1);
        registry.register(scanner2);

        await registry.dispatchClose();

        expect(scanner1.closeCalled).toBe(true);
        expect(scanner2.closeCalled).toBe(true);
    });

    test('should clear all scanner states', async () => {
        const scanner = new MockScanner();
        scanner.results = ['data'];
        registry.register(scanner);

        registry.clearAll();

        expect(scanner.results).toEqual([]);
    });

    test('should reset registry completely', async () => {
        const scanner = new MockScanner();
        registry.register(scanner);

        registry.reset();

        expect(registry.count).toBe(0);
    });
});
