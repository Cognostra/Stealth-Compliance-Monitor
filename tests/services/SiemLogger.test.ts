/**
 * SIEM Logger Tests
 */

import * as fs from 'fs';
import { SiemLogger, SecurityIssue, EcsEvent } from '../../src/services/SiemLogger';

// Mock fs module
jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

// Mock config
jest.mock('../../src/config/compliance.config', () => ({
    createConfig: jest.fn(() => ({
        siem: {
            enabled: true,
            webhookUrl: 'https://splunk.example.com/services/collector',
            logFilePath: 'logs/test-security.log',
        },
    })),
}));

// Mock compliance-map
jest.mock('../../src/data/compliance-map', () => ({
    getComplianceTags: jest.fn(() => ['PCI-DSS', 'OWASP']),
}));

// Mock logger
jest.mock('../../src/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn(),
    },
}));

// Mock fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('SiemLogger', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockFs.existsSync.mockReturnValue(true);
        mockFs.appendFileSync.mockReturnValue(undefined);
        mockFetch.mockResolvedValue({ ok: true });
        SiemLogger.clearBuffer();
    });

    describe('toEcsFormat', () => {
        it('should convert SecurityIssue to ECS format', () => {
            const issue: SecurityIssue = {
                id: 'xss-vulnerability',
                severity: 'high',
                description: 'Cross-site scripting vulnerability found',
                targetUrl: 'https://example.com/page',
                timestamp: '2026-01-16T10:00:00Z',
                category: 'security',
            };

            const ecsEvent = SiemLogger.toEcsFormat(issue);

            expect(ecsEvent['@timestamp']).toBe('2026-01-16T10:00:00Z');
            expect(ecsEvent.event.kind).toBe('alert');
            expect(ecsEvent.event.severity).toBe(3); // high = 3
            expect(ecsEvent.rule?.id).toBe('xss-vulnerability');
            expect(ecsEvent.url?.full).toBe('https://example.com/page');
            expect(ecsEvent.url?.domain).toBe('example.com');
        });

        it('should map severity to numeric value', () => {
            const severities = [
                { severity: 'critical', expected: 4 },
                { severity: 'high', expected: 3 },
                { severity: 'medium', expected: 2 },
                { severity: 'low', expected: 1 },
                { severity: 'info', expected: 0 },
            ];

            for (const { severity, expected } of severities) {
                const issue: SecurityIssue = {
                    id: 'test',
                    severity,
                    targetUrl: 'https://example.com',
                };
                const ecsEvent = SiemLogger.toEcsFormat(issue);
                expect(ecsEvent.event.severity).toBe(expected);
            }
        });

        it('should include CVE/CVSS info when present', () => {
            const issue: SecurityIssue = {
                id: 'vulnerable-library',
                severity: 'critical',
                targetUrl: 'https://example.com',
                cveId: 'CVE-2021-44228',
                cvssScore: 10.0,
            };

            const ecsEvent = SiemLogger.toEcsFormat(issue);

            expect(ecsEvent.vulnerability?.id).toBe('CVE-2021-44228');
            expect(ecsEvent.vulnerability?.score?.base).toBe(10.0);
            expect(ecsEvent.vulnerability?.score?.version).toBe('3.1');
        });

        it('should handle invalid URLs gracefully', () => {
            const issue: SecurityIssue = {
                id: 'test',
                severity: 'low',
                targetUrl: 'not-a-valid-url',
            };

            const ecsEvent = SiemLogger.toEcsFormat(issue);

            expect(ecsEvent.url).toBeUndefined();
        });
    });

    describe('logVulnerability', () => {
        it('should buffer events', async () => {
            const issue: SecurityIssue = {
                id: 'test-issue',
                severity: 'high',
                targetUrl: 'https://example.com',
            };

            await SiemLogger.logVulnerability(issue);

            expect(SiemLogger.getBufferedCount()).toBe(1);
        });

        it('should auto-flush when buffer is full', async () => {
            // Fill buffer to capacity
            for (let i = 0; i < 50; i++) {
                await SiemLogger.logVulnerability({
                    id: `test-${i}`,
                    severity: 'low',
                    targetUrl: 'https://example.com',
                });
            }

            expect(mockFs.appendFileSync).toHaveBeenCalled();
        });

        it('should skip when SIEM is disabled', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({ siem: { enabled: false } });

            await SiemLogger.logVulnerability({
                id: 'test',
                severity: 'high',
                targetUrl: 'https://example.com',
            });

            expect(SiemLogger.getBufferedCount()).toBe(0);
        });
    });

    describe('logBatch', () => {
        beforeEach(() => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                siem: {
                    enabled: true,
                    webhookUrl: 'https://splunk.example.com/services/collector',
                    logFilePath: 'logs/test-security.log',
                },
            });
        });

        it('should log multiple issues at once', async () => {
            const issues: SecurityIssue[] = [
                { id: 'issue-1', severity: 'high', targetUrl: 'https://example.com' },
                { id: 'issue-2', severity: 'medium', targetUrl: 'https://example.com' },
                { id: 'issue-3', severity: 'low', targetUrl: 'https://example.com' },
            ];

            await SiemLogger.logBatch(issues);

            expect(mockFs.appendFileSync).toHaveBeenCalled();
            const writeCall = mockFs.appendFileSync.mock.calls[0];
            const loggedData = writeCall[1] as string;
            const lines = loggedData.trim().split('\n');
            expect(lines.length).toBe(3);
        });
    });

    describe('flush', () => {
        beforeEach(() => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                siem: {
                    enabled: true,
                    webhookUrl: 'https://splunk.example.com/services/collector',
                    logFilePath: 'logs/test-security.log',
                },
            });
        });

        it('should write events to file in NDJSON format', async () => {
            SiemLogger.clearBuffer();
            await SiemLogger.logVulnerability({
                id: 'test',
                severity: 'high',
                targetUrl: 'https://example.com',
            });

            await SiemLogger.flush();

            expect(mockFs.appendFileSync).toHaveBeenCalled();
            const writeCall = mockFs.appendFileSync.mock.calls[0];
            const loggedData = writeCall[1] as string;
            // Should be valid JSON
            expect(() => JSON.parse(loggedData.trim())).not.toThrow();
        });

        it('should create log directory if not exists', async () => {
            mockFs.existsSync.mockReturnValue(false);
            mockFs.mkdirSync.mockReturnValue(undefined);

            await SiemLogger.logVulnerability({
                id: 'test',
                severity: 'high',
                targetUrl: 'https://example.com',
            });
            await SiemLogger.flush();

            expect(mockFs.mkdirSync).toHaveBeenCalledWith(expect.any(String), { recursive: true });
        });

        it('should send to webhook', async () => {
            await SiemLogger.logVulnerability({
                id: 'test',
                severity: 'high',
                targetUrl: 'https://example.com',
            });

            await SiemLogger.flush();

            expect(mockFetch).toHaveBeenCalledWith(
                'https://splunk.example.com/services/collector',
                expect.objectContaining({
                    method: 'POST',
                })
            );
        });

        it('should not call fetch if buffer is empty', async () => {
            SiemLogger.clearBuffer();
            
            await SiemLogger.flush();

            expect(mockFetch).not.toHaveBeenCalled();
        });
    });

    describe('logScanCompletion', () => {
        beforeEach(() => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                siem: {
                    enabled: true,
                    webhookUrl: 'https://splunk.example.com/services/collector',
                    logFilePath: 'logs/test-security.log',
                },
            });
        });

        it('should log scan completion event', async () => {
            await SiemLogger.logScanCompletion({
                targetUrl: 'https://example.com',
                duration: 30000,
                passed: true,
                criticalCount: 0,
                highCount: 2,
                scanId: 'scan-123',
            });

            expect(mockFs.appendFileSync).toHaveBeenCalled();
            const writeCall = mockFs.appendFileSync.mock.calls[0];
            const loggedData = writeCall[1] as string;
            const event = JSON.parse(loggedData.trim());
            expect(event.event.action).toBe('scan_completed');
            expect(event.event.outcome).toBe('success');
        });

        it('should mark failed scans', async () => {
            await SiemLogger.logScanCompletion({
                targetUrl: 'https://example.com',
                duration: 30000,
                passed: false,
                criticalCount: 3,
                highCount: 5,
            });

            const writeCall = mockFs.appendFileSync.mock.calls[0];
            const loggedData = writeCall[1] as string;
            const event = JSON.parse(loggedData.trim());
            expect(event.event.outcome).toBe('failure');
            expect(event.event.severity).toBe(4); // Critical issues
        });
    });

    describe('logAuthEvent', () => {
        beforeEach(() => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                siem: {
                    enabled: true,
                    webhookUrl: '',
                    logFilePath: 'logs/test-security.log',
                },
            });
        });

        it('should log authentication events', async () => {
            await SiemLogger.logAuthEvent({
                targetUrl: 'https://example.com',
                success: true,
                method: 'oauth',
                duration: 2000,
            });

            expect(SiemLogger.getBufferedCount()).toBe(1);
        });

        it('should log failed auth with error', async () => {
            await SiemLogger.logAuthEvent({
                targetUrl: 'https://example.com',
                success: false,
                method: 'password',
                error: 'Invalid credentials',
            });

            expect(SiemLogger.getBufferedCount()).toBe(1);
        });
    });

    describe('buffer management', () => {
        it('should clear buffer', () => {
            SiemLogger.clearBuffer();
            expect(SiemLogger.getBufferedCount()).toBe(0);
        });

        it('should track buffer count', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                siem: { enabled: true, logFilePath: 'logs/test.log' },
            });

            SiemLogger.clearBuffer();
            
            await SiemLogger.logVulnerability({
                id: 'test-1',
                severity: 'low',
                targetUrl: 'https://example.com',
            });

            expect(SiemLogger.getBufferedCount()).toBe(1);

            await SiemLogger.logVulnerability({
                id: 'test-2',
                severity: 'low',
                targetUrl: 'https://example.com',
            });

            expect(SiemLogger.getBufferedCount()).toBe(2);
        });
    });
});
