/**
 * Tests for TrendService Input Validation
 *
 * Validates Zod schema validation and security protections
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { TrendService, type TrendDataPoint } from '../../../src/v3/services/TrendService.js';

// Mock logger
const mockLogger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
};

describe('TrendService Input Validation', () => {
    let service: TrendService;
    let tempDir: string;

    beforeEach(() => {
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trend-test-'));
        service = new TrendService(mockLogger as any, tempDir);
    });

    afterEach(() => {
        if (fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });

    describe('Valid Input Handling', () => {
        it('should accept valid trend data point', () => {
            const validRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run-123',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(validRecord)).not.toThrow();
        });

        it('should accept score of 0', () => {
            const record: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 0,
                performanceScore: 0,
                securityCritical: 0,
            };

            expect(() => service.addRecord(record)).not.toThrow();
        });

        it('should accept score of 100', () => {
            const record: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 100,
                performanceScore: 100,
                securityCritical: 0,
            };

            expect(() => service.addRecord(record)).not.toThrow();
        });

        it('should accept high security critical count', () => {
            const record: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 50,
                performanceScore: 50,
                securityCritical: 999,
            };

            expect(() => service.addRecord(record)).not.toThrow();
        });
    });

    describe('Invalid URL Validation', () => {
        it('should reject invalid URL format', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'not-a-valid-url',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid trend data point/);
        });

        it('should reject empty URL', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: '',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject relative URL', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: '/path/to/page',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });
    });

    describe('Prototype Pollution Protection', () => {
        it('should reject __proto__ as targetUrl', () => {
            const maliciousRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: '__proto__',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(maliciousRecord)).toThrow(/reserved keyword/);
        });

        it('should reject constructor as targetUrl', () => {
            const maliciousRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'constructor',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(maliciousRecord)).toThrow(/reserved keyword/);
        });

        it('should reject prototype as targetUrl', () => {
            const maliciousRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'prototype',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(maliciousRecord)).toThrow(/reserved keyword/);
        });
    });

    describe('Score Range Validation', () => {
        it('should reject overallScore < 0', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: -1,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid trend data point/);
        });

        it('should reject overallScore > 100', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 101,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid overallScore/);
        });

        it('should reject performanceScore < 0', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: -10,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid trend data point/);
        });

        it('should reject performanceScore > 100', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 150,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid performanceScore/);
        });

        it('should reject negative securityCritical', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: -5,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow(/Invalid securityCritical/);
        });
    });

    describe('Required Field Validation', () => {
        it('should reject missing timestamp', () => {
            const invalidRecord: any = {
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject missing runId', () => {
            const invalidRecord: any = {
                timestamp: new Date().toISOString(),
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject empty runId', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: '',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject invalid timestamp format', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: 'not-a-valid-timestamp',
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });
    });

    describe('Type Validation', () => {
        it('should reject non-number overallScore', () => {
            const invalidRecord: any = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: '85',
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject NaN score', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: NaN,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });

        it('should reject Infinity score', () => {
            const invalidRecord: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: Infinity,
                performanceScore: 90,
                securityCritical: 2,
            };

            expect(() => service.addRecord(invalidRecord)).toThrow();
        });
    });

    describe('Functional Tests', () => {
        it('should store valid records', () => {
            const record: TrendDataPoint = {
                timestamp: new Date().toISOString(),
                runId: 'test-run',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                securityCritical: 2,
            };

            service.addRecord(record);

            const history = service.getHistory('https://example.com');
            expect(history).toHaveLength(1);
            expect(history[0]).toEqual(record);
        });

        it('should limit history to 50 records', () => {
            for (let i = 0; i < 60; i++) {
                const record: TrendDataPoint = {
                    timestamp: new Date(Date.now() + i * 1000).toISOString(),
                    runId: `test-run-${i}`,
                    targetUrl: 'https://example.com',
                    overallScore: 85,
                    performanceScore: 90,
                    securityCritical: i,
                };

                service.addRecord(record);
            }

            const history = service.getHistory('https://example.com');
            expect(history).toHaveLength(50);

            // Should keep the most recent 50
            expect(history[0].runId).toBe('test-run-10');
            expect(history[49].runId).toBe('test-run-59');
        });

        it('should calculate stats correctly', () => {
            const records: TrendDataPoint[] = [
                {
                    timestamp: new Date(Date.now() - 2000).toISOString(),
                    runId: 'run-1',
                    targetUrl: 'https://example.com',
                    overallScore: 80,
                    performanceScore: 80,
                    securityCritical: 0,
                },
                {
                    timestamp: new Date(Date.now() - 1000).toISOString(),
                    runId: 'run-2',
                    targetUrl: 'https://example.com',
                    overallScore: 90,
                    performanceScore: 90,
                    securityCritical: 0,
                },
                {
                    timestamp: new Date().toISOString(),
                    runId: 'run-3',
                    targetUrl: 'https://example.com',
                    overallScore: 100,
                    performanceScore: 100,
                    securityCritical: 0,
                },
            ];

            records.forEach(r => service.addRecord(r));

            const stats = service.getStats('https://example.com');

            expect(stats.avgScore).toBe(90);
            expect(stats.trend).toBe('up');
        });
    });
});
