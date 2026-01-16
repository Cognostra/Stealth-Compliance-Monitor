/**
 * Webhook Service Tests
 */

import { jest } from '@jest/globals';
import { WebhookService, WebhookPayload, WebhookResult } from '../../src/services/WebhookService.js';

// Mock config
jest.mock('../../src/config/compliance.config.js', () => ({
    createConfig: jest.fn(() => ({
        webhook: {
            url: 'https://hooks.slack.com/services/test',
            secret: 'test-secret',
            events: 'all',
        },
        USER_AGENT: 'Test-Agent/1.0',
        targetUrl: 'https://example.com',
    })),
}));

// Mock logger
jest.mock('../../src/utils/logger.js', () => ({
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

describe('WebhookService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockFetch.mockReset();
    });

    describe('sendAlert', () => {
        const mockScanSummary = {
            securityCritical: 2,
            securityHigh: 3,
            highRiskAlerts: 1,
            mediumRiskAlerts: 5,
            healthScore: 75,
            performanceScore: 85,
            accessibilityScore: 80,
            seoScore: 90,
            vulnerableLibraries: 3,
        };

        it('should send webhook alert successfully', async () => {
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            const result = await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(true);
            expect(mockFetch).toHaveBeenCalledWith(
                'https://hooks.slack.com/services/test',
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/json',
                    }),
                })
            );
        });

        it('should return success when no webhook configured', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({ webhook: null });

            const result = await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(true);
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it('should skip when filter is critical and no critical issues', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://hooks.slack.com/services/test',
                    events: 'critical',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });

            const result = await WebhookService.sendAlert(
                { ...mockScanSummary, securityCritical: 0, securityHigh: 0 },
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(true);
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it('should include HMAC signature when secret is configured', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://hooks.slack.com/services/test',
                    secret: 'my-secret',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(mockFetch).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    headers: expect.objectContaining({
                        'X-Compliance-Signature': expect.stringMatching(/^sha256=/),
                    }),
                })
            );
        });

        it('should include comparison data when provided', async () => {
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html',
                {
                    previousScore: 70,
                    scoreDiff: 5,
                    trend: 'improving',
                    newIssues: 1,
                    resolvedIssues: 3,
                }
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.attachments[0].fields).toContainEqual(
                expect.objectContaining({ title: 'Trend' })
            );
        });

        it('should retry on server error', async () => {
            mockFetch
                .mockResolvedValueOnce({ ok: false, status: 500, statusText: 'Internal Server Error' })
                .mockResolvedValueOnce({ ok: true, status: 200 });

            const result = await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(true);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it('should not retry on client error', async () => {
            mockFetch.mockResolvedValueOnce({ ok: false, status: 400, statusText: 'Bad Request' });

            const result = await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(false);
            expect(result.statusCode).toBe(400);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it('should handle network errors with retries', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const result = await WebhookService.sendAlert(
                mockScanSummary,
                'https://example.com',
                '/reports/test.html'
            );

            expect(result.success).toBe(false);
            expect(result.error).toContain('Network error');
            expect(mockFetch).toHaveBeenCalledTimes(3); // 3 retries
        });
    });

    describe('webhook type detection', () => {
        it('should format for Slack', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://hooks.slack.com/services/T123/B456/xyz',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 0, securityHigh: 0, healthScore: 95 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.text).toBeDefined();
            expect(body.attachments).toBeDefined();
        });

        it('should format for Microsoft Teams', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://outlook.office.com/webhook/123',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 1, securityHigh: 0, healthScore: 85 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body['@type']).toBe('MessageCard');
            expect(body.themeColor).toBeDefined();
        });

        it('should format for Discord', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://discord.com/api/webhooks/123/abc',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 0, securityHigh: 2, healthScore: 75 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.embeds).toBeDefined();
            expect(body.embeds[0].color).toBeDefined();
        });

        it('should use generic format for unknown webhooks', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 0, securityHigh: 0, healthScore: 90 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.event).toBe('scan_completed');
            expect(body.target).toBe('https://example.com');
        });
    });

    describe('status determination', () => {
        it('should return FAIL status for critical issues', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 5, securityHigh: 0, healthScore: 50 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.status).toBe('FAIL');
        });

        it('should return WARNING status for high issues only', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 0, securityHigh: 3, healthScore: 70 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.status).toBe('WARNING');
        });

        it('should return PASS status when no high or critical issues', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            await WebhookService.sendAlert(
                { securityCritical: 0, securityHigh: 0, healthScore: 95 },
                'https://example.com',
                '/reports/test.html'
            );

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.status).toBe('PASS');
        });
    });

    describe('sendCustomEvent', () => {
        it('should send custom event', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
                targetUrl: 'https://example.com',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            const result = await WebhookService.sendCustomEvent(
                'custom_event',
                { key: 'value', count: 42 }
            );

            expect(result.success).toBe(true);
            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.event).toBe('custom_event');
            expect(body.data.key).toBe('value');
        });

        it('should return success when no webhook configured', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({ webhook: null });

            const result = await WebhookService.sendCustomEvent('test', {});

            expect(result.success).toBe(true);
            expect(mockFetch).not.toHaveBeenCalled();
        });
    });

    describe('testConnection', () => {
        it('should send test message', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({
                webhook: {
                    url: 'https://custom-webhook.example.com/notify',
                    events: 'all',
                },
                USER_AGENT: 'Test-Agent/1.0',
                targetUrl: 'https://example.com',
            });
            mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

            const result = await WebhookService.testConnection();

            expect(result.success).toBe(true);
            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            expect(body.event).toBe('test');
        });

        it('should return error when no webhook configured', async () => {
            const { createConfig } = require('../../src/config/compliance.config');
            createConfig.mockReturnValue({ webhook: null });

            const result = await WebhookService.testConnection();

            expect(result.success).toBe(false);
            expect(result.error).toContain('No webhook URL configured');
        });
    });
});
