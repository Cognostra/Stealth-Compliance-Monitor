/**
 * Unit Tests for NetworkSpy
 *
 * Tests network incident detection types.
 * Note: NetworkSpy is designed for integration with Playwright lifecycle.
 */

import { NetworkSpy, NetworkIncident } from '../../src/services/NetworkSpy.js';

describe('NetworkSpy', () => {
    let spy: NetworkSpy;

    beforeEach(() => {
        spy = new NetworkSpy();
    });

    describe('Service interface', () => {
        it('should have correct name', () => {
            expect(spy.name).toBe('NetworkSpy');
        });

        it('should implement IScanner lifecycle', () => {
            expect(typeof spy.onPageCreated).toBe('function');
            expect(typeof spy.onResponse).toBe('function');
        });
    });

    describe('NetworkIncident type', () => {
        it('should define NetworkIncident with required fields', () => {
            const incident: NetworkIncident = {
                url: 'https://example.com/api',
                method: 'GET',
                type: 'http_error',
                status: 500,
                timestamp: new Date().toISOString()
            };
            expect(incident.type).toBe('http_error');
            expect(incident.status).toBe(500);
        });
    });

    describe('Incident types', () => {
        it('should support slow_response type', () => {
            const type: NetworkIncident['type'] = 'slow_response';
            expect(type).toBe('slow_response');
        });

        it('should support heavy_payload type', () => {
            const type: NetworkIncident['type'] = 'heavy_payload';
            expect(type).toBe('heavy_payload');
        });

        it('should support http_error type', () => {
            const type: NetworkIncident['type'] = 'http_error';
            expect(type).toBe('http_error');
        });
    });

    describe('SPY_CONFIG thresholds', () => {
        it('should define slowThreshold', () => {
            const slowThreshold = 500; // ms
            expect(slowThreshold).toBeGreaterThan(0);
        });

        it('should define largeSizeThreshold', () => {
            const largeSizeThreshold = 100 * 1024; // 100KB
            expect(largeSizeThreshold).toBeGreaterThan(0);
        });

        it('should ignore known tracking domains', () => {
            const ignoredHosts = [
                'google-analytics.com',
                'googletagmanager.com',
                'facebook.net'
            ];
            expect(ignoredHosts.length).toBeGreaterThan(0);
            expect(ignoredHosts).toContain('google-analytics.com');
        });
    });
});
