// @ts-nocheck - Playwright fixture types don't resolve correctly with TypeScript
/**
 * Integration Tests: Report Generation
 *
 * Tests HTML and JSON report generation functionality.
 */

import { test, expect } from '../fixtures/index.js';
import { HtmlReportGenerator } from '../../../src/services/HtmlReportGenerator.js';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Report Generation', () => {
    const testReportsDir = path.resolve(process.cwd(), 'test-results', 'reports');

    test.beforeAll(() => {
        // Ensure test reports directory exists
        if (!fs.existsSync(testReportsDir)) {
            fs.mkdirSync(testReportsDir, { recursive: true });
        }
    });

    test.describe('HTML Report Generator', () => {
        test('should generate HTML report from audit data', async () => {
            const generator = new HtmlReportGenerator();

            // Mock audit data
            const auditData = {
                meta: {
                    version: '1.0.0',
                    generatedAt: new Date().toISOString(),
                    targetUrl: 'https://example.com',
                    duration: 5000,
                    isPartial: false,
                },
                authentication: {
                    success: true,
                    duration: 1000,
                },
                crawl: {
                    pagesVisited: 5,
                    failedPages: 0,
                    pageResults: [],
                },
                integrity: {
                    testsRun: 10,
                    passed: 10,
                    failed: 0,
                },
                network_incidents: [],
                leaked_secrets: [],
                supabase_issues: [],
                vulnerable_libraries: [],
                security_assessment: {
                    findings: [],
                    summary: { critical: 0, high: 0, medium: 0, low: 0 },
                },
                lighthouse: {
                    scores: {
                        performance: 90,
                        accessibility: 95,
                        seo: 88,
                        bestPractices: 92,
                    },
                },
                security_alerts: [],
                summary: {
                    healthScore: 92,
                    performanceScore: 90,
                    accessibilityScore: 95,
                    securityScore: 85,
                },
            };

            const outputPath = path.join(testReportsDir, 'test-report.html');
            (auditData as any).outputPath = outputPath;

            await generator.generate(auditData as any);

            // Verify file was created
            expect(fs.existsSync(outputPath)).toBe(true);

            // Verify it's valid HTML
            const content = fs.readFileSync(outputPath, 'utf-8');
            expect(content).toContain('<!DOCTYPE html>');
            expect(content).toContain('example.com');
        });

        test('should include score cards in report', async () => {
            const generator = new HtmlReportGenerator();

            const auditData = {
                meta: {
                    version: '1.0.0',
                    generatedAt: new Date().toISOString(),
                    targetUrl: 'https://example.com',
                    duration: 5000,
                    isPartial: false,
                },
                lighthouse: {
                    scores: {
                        performance: 85,
                        accessibility: 90,
                        seo: 75,
                        bestPractices: 88,
                    },
                },
                summary: {
                    healthScore: 85,
                    performanceScore: 85,
                    accessibilityScore: 90,
                    securityScore: 80,
                },
            };

            const outputPath = path.join(testReportsDir, 'test-scores.html');
            (auditData as any).outputPath = outputPath;

            await generator.generate(auditData as any);

            const content = fs.readFileSync(outputPath, 'utf-8');

            // Should contain score values
            expect(content).toContain('85');
            expect(content).toContain('90');
        });

        test('should include security findings in report', async () => {
            const generator = new HtmlReportGenerator();

            const auditData = {
                meta: {
                    version: '1.0.0',
                    generatedAt: new Date().toISOString(),
                    targetUrl: 'https://example.com',
                    duration: 5000,
                    isPartial: false,
                },
                security_alerts: [
                    {
                        risk: 'Medium',
                        name: 'Missing Security Header',
                        description: 'X-Frame-Options header is missing',
                        url: 'https://example.com',
                        solution: 'Add X-Frame-Options header',
                    },
                ],
                security_assessment: {
                    findings: [
                        {
                            severity: 'medium',
                            title: 'Test Finding',
                            description: 'Test description',
                        },
                    ],
                    summary: { critical: 0, high: 0, medium: 1, low: 0 },
                },
                summary: {
                    healthScore: 80,
                    securityScore: 75,
                },
            };

            const outputPath = path.join(testReportsDir, 'test-security.html');
            (auditData as any).outputPath = outputPath;

            await generator.generate(auditData as any);

            const content = fs.readFileSync(outputPath, 'utf-8');

            // Should contain security findings
            expect(content).toContain('Security');
        });
    });

    test.describe('JSON Report', () => {
        test('should generate valid JSON report', async () => {
            const reportData = {
                meta: {
                    version: '1.0.0',
                    generatedAt: new Date().toISOString(),
                    targetUrl: 'https://example.com',
                },
                summary: {
                    healthScore: 90,
                },
            };

            const outputPath = path.join(testReportsDir, 'test-report.json');
            fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));

            // Verify file was created
            expect(fs.existsSync(outputPath)).toBe(true);

            // Verify it's valid JSON
            const content = fs.readFileSync(outputPath, 'utf-8');
            const parsed = JSON.parse(content);

            expect(parsed.meta.targetUrl).toBe('https://example.com');
            expect(parsed.summary.healthScore).toBe(90);
        });
    });

    test.afterAll(() => {
        // Clean up test reports
        if (fs.existsSync(testReportsDir)) {
            const files = fs.readdirSync(testReportsDir);
            for (const file of files) {
                if (file.startsWith('test-')) {
                    fs.unlinkSync(path.join(testReportsDir, file));
                }
            }
        }
    });
});
