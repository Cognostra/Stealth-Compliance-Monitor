/**
 * Unit Tests for NetworkSpy
 *
 * Tests network request/response monitoring and incident detection.
 */

import { NetworkSpy, NetworkIncident } from '../../src/services/NetworkSpy.js';

describe('NetworkSpy', () => {
    let spy: NetworkSpy;

    beforeEach(() => {
        spy = new NetworkSpy();
    });

    describe('IScanner interface', () => {
        it('should have correct name', () => {
            expect(spy.name).toBe('NetworkSpy');
        });

        it('should return empty incidents initially', () => {
            expect(spy.getResults()).toEqual([]);
        });

        it('should clear incidents', () => {
            // Add an incident manually via type casting
            (spy as any).incidents.push({
                url: 'https://example.com/api',
                method: 'GET',
                type: 'http_error',
                status: 500,
                timestamp: new Date().toISOString()
            });

            expect(spy.getResults().length).toBeGreaterThan(0);

            spy.clear();

            expect(spy.getResults()).toEqual([]);
        });
    });

    describe('Incident types', () => {
        it('should store slow_response incidents', () => {
            (spy as any).incidents.push({
                url: 'https://example.com/slow-api',
                method: 'GET',
                type: 'slow_response',
                status: 200,
                duration: 3000,
                timestamp: new Date().toISOString()
            });

            const incidents = spy.getResults();
            expect(incidents.length).toBe(1);
            expect(incidents[0].type).toBe('slow_response');
            expect(incidents[0].duration).toBe(3000);
        });

        it('should store heavy_payload incidents', () => {
            (spy as any).incidents.push({
                url: 'https://example.com/large-file',
                method: 'GET',
                type: 'heavy_payload',
                status: 200,
                sizeBytes: 2 * 1024 * 1024,
                timestamp: new Date().toISOString()
            });

            const incidents = spy.getResults();
            expect(incidents.length).toBe(1);
            expect(incidents[0].type).toBe('heavy_payload');
            expect(incidents[0].sizeBytes).toBe(2 * 1024 * 1024);
        });

        it('should store http_error incidents', () => {
            (spy as any).incidents.push({
                url: 'https://example.com/error',
                method: 'GET',
                type: 'http_error',
                status: 500,
                timestamp: new Date().toISOString()
            });

            const incidents = spy.getResults();
            expect(incidents.length).toBe(1);
            expect(incidents[0].type).toBe('http_error');
            expect(incidents[0].status).toBe(500);
        });
    });

    describe('getIncidents alias', () => {
        beforeEach(() => {
            (spy as any).incidents = [
                { url: 'https://site1.com/api', method: 'GET', type: 'http_error', status: 404, timestamp: new Date().toISOString() },
                { url: 'https://site2.com/api', method: 'POST', type: 'slow_response', status: 200, duration: 1000, timestamp: new Date().toISOString() }
            ];
        });

        it('should return all incidents via getResults', () => {
            const incidents = spy.getResults();
            expect(incidents.length).toBe(2);
        });

        it('should return all incidents via getIncidents alias', () => {
            const incidents = spy.getIncidents();
            expect(incidents.length).toBe(2);
        });
    });

    describe('incident data structure', () => {
        it('should include url in incident', () => {
            (spy as any).incidents.push({
                url: 'https://example.com/api/test',
                method: 'GET',
                type: 'http_error',
                status: 404,
                timestamp: new Date().toISOString()
            });

            expect(spy.getResults()[0].url).toBe('https://example.com/api/test');
        });

        it('should include method in incident', () => {
            (spy as any).incidents.push({
                url: 'https://example.com/api',
                method: 'POST',
                type: 'http_error',
                status: 500,
                timestamp: new Date().toISOString()
            });

            expect(spy.getResults()[0].method).toBe('POST');
        });

        it('should include timestamp in incident', () => {
            const now = new Date().toISOString();
            (spy as any).incidents.push({
                url: 'https://example.com/api',
                method: 'GET',
                type: 'http_error',
                status: 500,
                timestamp: now
            });

            expect(spy.getResults()[0].timestamp).toBe(now);
        });
    });

    describe('onPageCreated lifecycle', () => {
        it('should attach to page only once', () => {
            const mockPage = {
                on: jest.fn(),
            } as any;

            spy.onPageCreated(mockPage);
            spy.onPageCreated(mockPage); // Second call

            // Should only set up listeners once
            expect((spy as any).page).toBe(mockPage);
        });
    });

    describe('incident filtering', () => {
        beforeEach(() => {
            (spy as any).incidents = [
                { url: 'https://api.site1.com/data', method: 'GET', type: 'http_error', status: 404, timestamp: new Date().toISOString() },
                { url: 'https://api.site2.com/data', method: 'GET', type: 'slow_response', status: 200, duration: 2000, timestamp: new Date().toISOString() },
                { url: 'https://api.site1.com/other', method: 'POST', type: 'heavy_payload', status: 200, sizeBytes: 500000, timestamp: new Date().toISOString() }
            ];
        });

        it('should be able to filter by type', () => {
            const incidents = spy.getResults();
            const errors = incidents.filter((i: NetworkIncident) => i.type === 'http_error');
            expect(errors.length).toBe(1);
        });

        it('should be able to filter by status', () => {
            const incidents = spy.getResults();
            const successResponses = incidents.filter((i: NetworkIncident) => i.status === 200);
            expect(successResponses.length).toBe(2);
        });
    });
});
