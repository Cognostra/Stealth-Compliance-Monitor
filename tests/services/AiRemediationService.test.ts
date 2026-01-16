/**
 * AI Remediation Service Tests
 */

import { jest } from '@jest/globals';
import { AiRemediationService, RemediationRequest, RemediationResponse } from '../../src/services/AiRemediationService.js';

// Mock config
jest.mock('../../src/config/env.js', () => ({
    getConfig: jest.fn(() => ({
        ENABLE_AI: false,
        OPENAI_API_KEY: '',
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

describe('AiRemediationService', () => {
    let service: AiRemediationService;

    beforeEach(() => {
        jest.clearAllMocks();
        mockFetch.mockReset();
        service = new AiRemediationService();
    });

    describe('generateFix (AI disabled)', () => {
        it('should return mock fix when AI is disabled', async () => {
            const request: RemediationRequest = {
                type: 'xss',
                details: 'Cross-site scripting vulnerability in user input',
                severity: 'high',
            };

            const response = await service.generateFix(request);

            expect(response.isAiGenerated).toBe(false);
            expect(response.code).toContain('DOMPurify');
            expect(response.effort).toBe('medium');
            expect(response.references).toBeDefined();
        });

        it('should return SQL injection fix', async () => {
            const request: RemediationRequest = {
                type: 'sqli',
                details: 'SQL injection in search parameter',
                severity: 'critical',
            };

            const response = await service.generateFix(request);

            expect(response.code).toContain('parameterized');
            expect(response.isAiGenerated).toBe(false);
        });

        it('should return CSRF fix', async () => {
            const request: RemediationRequest = {
                type: 'csrf',
                details: 'Missing CSRF token',
                severity: 'high',
            };

            const response = await service.generateFix(request);

            expect(response.isAiGenerated).toBe(false);
            expect(response.effort).toBe('medium');
        });

        it('should return accessibility contrast fix', async () => {
            const request: RemediationRequest = {
                type: 'a11y-contrast',
                details: 'Insufficient color contrast ratio',
                severity: 'medium',
            };

            const response = await service.generateFix(request);

            expect(response.code).toContain('contrast');
            expect(response.effort).toBe('low');
        });

        it('should return accessibility alt text fix', async () => {
            const request: RemediationRequest = {
                type: 'a11y-alt',
                details: 'Image missing alt attribute',
                severity: 'medium',
            };

            const response = await service.generateFix(request);

            expect(response.code).toContain('alt');
        });

        it('should return secret leak fix', async () => {
            const request: RemediationRequest = {
                type: 'secret-leak',
                details: 'API key exposed in source code',
                severity: 'critical',
            };

            const response = await service.generateFix(request);

            expect(response.code).toContain('process.env');
            expect(response.effort).toBe('high');
        });

        it('should return security headers fix', async () => {
            const request: RemediationRequest = {
                type: 'missing-header',
                details: 'Missing X-Frame-Options header',
                severity: 'medium',
            };

            const response = await service.generateFix(request);

            expect(response.code).toContain('helmet');
        });

        it('should return generic fix for unknown type', async () => {
            const request: RemediationRequest = {
                type: 'unknown-issue-type',
                details: 'Some unknown vulnerability',
                severity: 'low',
            };

            const response = await service.generateFix(request);

            expect(response.isAiGenerated).toBe(false);
            expect(response.code).toContain('AI REMEDIATION DISABLED');
        });
    });

    describe('generateFix (AI enabled)', () => {
        beforeEach(() => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-api-key',
            });
            service = new AiRemediationService();
        });

        it('should call OpenAI API when enabled', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{
                        message: {
                            content: `CODE:
\`\`\`javascript
// Secure fix
const sanitized = DOMPurify.sanitize(input);
\`\`\`

EXPLANATION:
Use DOMPurify to sanitize user input.

ALTERNATIVES:
Use escape-html library
`,
                        },
                    }],
                    usage: { total_tokens: 150 },
                }),
            });

            const request: RemediationRequest = {
                type: 'xss',
                details: 'XSS vulnerability',
                severity: 'high',
            };

            const response = await service.generateFix(request);

            expect(mockFetch).toHaveBeenCalledWith(
                'https://api.openai.com/v1/chat/completions',
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Authorization': 'Bearer test-api-key',
                    }),
                })
            );
            expect(response.isAiGenerated).toBe(true);
            expect(response.code).toContain('DOMPurify');
        });

        it('should fall back to mock fix on API error', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: async () => 'Unauthorized',
            });

            const request: RemediationRequest = {
                type: 'xss',
                details: 'XSS vulnerability',
                severity: 'high',
            };

            const response = await service.generateFix(request);

            expect(response.isAiGenerated).toBe(false);
        });

        it('should track token usage', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{
                        message: { content: 'CODE:\n```\nfix\n```\nEXPLANATION:\nfix' },
                    }],
                    usage: { total_tokens: 100 },
                }),
            });

            await service.generateFix({
                type: 'xss',
                details: 'test',
                severity: 'high',
            });

            expect(service.getTotalTokensUsed()).toBe(100);
        });
    });

    describe('generateBatchFixes', () => {
        it('should process multiple requests', async () => {
            const requests: RemediationRequest[] = [
                { type: 'xss', details: 'XSS issue 1', severity: 'high' },
                { type: 'sqli', details: 'SQL injection', severity: 'critical' },
                { type: 'a11y-contrast', details: 'Low contrast', severity: 'medium' },
            ];

            const result = await service.generateBatchFixes(requests);

            expect(result.fixes).toHaveLength(3);
            expect(result.failed).toHaveLength(0);
            expect(result.duration).toBeGreaterThan(0);
        });

        it('should handle mixed success/failure', async () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-api-key',
            });
            service = new AiRemediationService();

            // First call succeeds, second fails
            mockFetch
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'CODE:\n```\nfix\n```\nEXPLANATION:\nfix' } }],
                        usage: { total_tokens: 50 },
                    }),
                })
                .mockRejectedValueOnce(new Error('API error'))
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'CODE:\n```\nfix2\n```\nEXPLANATION:\nfix2' } }],
                        usage: { total_tokens: 50 },
                    }),
                });

            const requests: RemediationRequest[] = [
                { type: 'xss', details: 'Issue 1', severity: 'high' },
                { type: 'sqli', details: 'Issue 2', severity: 'high' },
                { type: 'csrf', details: 'Issue 3', severity: 'high' },
            ];

            const result = await service.generateBatchFixes(requests);

            // All should succeed because errors fall back to mock fixes
            expect(result.fixes).toHaveLength(3);
        });
    });

    describe('normalizeIssueType', () => {
        it('should handle various XSS naming patterns', async () => {
            const xssPatterns = [
                'xss',
                'XSS',
                'cross-site-scripting',
                'Cross Site Scripting',
                'cross_site_scripting',
            ];

            for (const pattern of xssPatterns) {
                const response = await service.generateFix({
                    type: pattern,
                    details: 'XSS test',
                    severity: 'high',
                });
                expect(response.code).toContain('DOMPurify');
            }
        });

        it('should handle SQL injection patterns', async () => {
            const patterns = ['sqli', 'SQLi', 'sql-injection', 'SQL_Injection'];

            for (const pattern of patterns) {
                const response = await service.generateFix({
                    type: pattern,
                    details: 'SQL test',
                    severity: 'high',
                });
                expect(response.code).toContain('parameterized');
            }
        });

        it('should handle accessibility patterns', async () => {
            const response = await service.generateFix({
                type: 'accessibility-contrast',
                details: 'Contrast issue',
                severity: 'medium',
            });
            expect(response.code).toContain('contrast');
        });
    });

    describe('utility methods', () => {
        it('should check if AI is enabled', () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: false,
                OPENAI_API_KEY: '',
            });
            service = new AiRemediationService();

            expect(service.isEnabled()).toBe(false);
        });

        it('should reset token counter', async () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-key',
            });
            service = new AiRemediationService();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{ message: { content: 'fix' } }],
                    usage: { total_tokens: 100 },
                }),
            });

            await service.generateFix({
                type: 'xss',
                details: 'test',
                severity: 'high',
            });

            expect(service.getTotalTokensUsed()).toBe(100);

            service.resetTokenCounter();

            expect(service.getTotalTokensUsed()).toBe(0);
        });
    });

    describe('response parsing', () => {
        it('should parse AI response with code block', async () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-key',
            });
            service = new AiRemediationService();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{
                        message: {
                            content: `CODE:
\`\`\`javascript
const fix = true;
\`\`\`

EXPLANATION:
This fixes the issue by doing X.

ALTERNATIVES:
- Alternative 1
- Alternative 2`,
                        },
                    }],
                    usage: { total_tokens: 100 },
                }),
            });

            const response = await service.generateFix({
                type: 'xss',
                details: 'test',
                severity: 'high',
            });

            expect(response.code).toBe('const fix = true;');
            expect(response.explanation).toContain('fixes the issue');
            expect(response.alternatives).toBeDefined();
            expect(response.alternatives?.length).toBeGreaterThan(0);
        });

        it('should handle response without proper formatting', async () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-key',
            });
            service = new AiRemediationService();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{
                        message: {
                            content: 'Just some plain text response without proper formatting',
                        },
                    }],
                    usage: { total_tokens: 50 },
                }),
            });

            const response = await service.generateFix({
                type: 'xss',
                details: 'test',
                severity: 'high',
            });

            expect(response.code).toBe('Just some plain text response without proper formatting');
            expect(response.isAiGenerated).toBe(true);
        });
    });

    describe('context inclusion', () => {
        it('should include all context in prompt', async () => {
            const { getConfig } = require('../../src/config/env');
            getConfig.mockReturnValue({
                ENABLE_AI: true,
                OPENAI_API_KEY: 'test-key',
            });
            service = new AiRemediationService();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    choices: [{ message: { content: 'fix' } }],
                    usage: { total_tokens: 100 },
                }),
            });

            await service.generateFix({
                type: 'xss',
                details: 'XSS in search field',
                context: 'React component with dangerouslySetInnerHTML',
                severity: 'high',
                element: '#search-input',
                currentValue: '<script>alert(1)</script>',
                complianceTags: ['OWASP A7', 'PCI-DSS 6.5.7'],
            }, ['React', 'TypeScript', 'Next.js']);

            const call = mockFetch.mock.calls[0];
            const body = JSON.parse(call[1].body);
            const prompt = body.messages[1].content;

            expect(prompt).toContain('React, TypeScript, Next.js');
            expect(prompt).toContain('XSS');
            expect(prompt).toContain('dangerouslySetInnerHTML');
            expect(prompt).toContain('#search-input');
            expect(prompt).toContain('OWASP A7');
        });
    });
});
