/**
 * Fleet Report Generator Tests
 */

import { jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import { FleetReportGenerator, FleetSiteResult, FleetSummary } from '../../src/services/FleetReportGenerator.js';

// Mock fs
jest.mock('fs', () => ({
    existsSync: jest.fn(() => true),
    mkdirSync: jest.fn(),
    writeFileSync: jest.fn(),
    readFileSync: jest.fn(),
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

describe('FleetReportGenerator', () => {
    let generator: FleetReportGenerator;
    const mockResults: FleetSiteResult[] = [
        {
            url: 'https://example.com',
            domain: 'example.com',
            healthScore: 85,
            reportPath: './reports/example.com/report.html',
            criticalIssues: 1,
            highIssues: 3,
            status: 'pass',
            scanDuration: 45000,
            timestamp: new Date('2025-01-15T10:00:00Z').toISOString(),
            scores: {
                accessibility: 90,
                security: 80,
                seo: 85,
                performance: 88,
            },
            comparison: {
                previousScore: 80,
                trend: 'improving',
            },
        },
        {
            url: 'https://app.example.com',
            domain: 'app.example.com',
            healthScore: 72,
            reportPath: './reports/app.example.com/report.html',
            criticalIssues: 2,
            highIssues: 5,
            status: 'fail',
            scanDuration: 52000,
            timestamp: new Date('2025-01-15T10:05:00Z').toISOString(),
            scores: {
                accessibility: 75,
                security: 70,
                seo: 68,
                performance: 80,
            },
            comparison: {
                previousScore: 75,
                trend: 'declining',
            },
        },
        {
            url: 'https://api.example.com',
            domain: 'api.example.com',
            healthScore: 95,
            reportPath: './reports/api.example.com/report.html',
            criticalIssues: 0,
            highIssues: 1,
            status: 'pass',
            scanDuration: 30000,
            timestamp: new Date('2025-01-15T10:10:00Z').toISOString(),
            scores: {
                accessibility: 95,
                security: 98,
                seo: 92,
                performance: 94,
            },
        },
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        generator = new FleetReportGenerator('./reports');
    });

    describe('generate', () => {
        it('should generate HTML dashboard and JSON summary', async () => {
            const result = await generator.generate(mockResults);

            expect(fs.writeFileSync).toHaveBeenCalledTimes(2);

            // First call is HTML
            const htmlCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
            expect(htmlCall[0]).toContain('fleet-dashboard.html');
            expect(htmlCall[1]).toContain('<!DOCTYPE html>');

            // Second call is JSON
            const jsonCall = (fs.writeFileSync as jest.Mock).mock.calls[1];
            expect(jsonCall[0]).toContain('fleet-summary.json');
        });

        it('should return correct output path', async () => {
            const result = await generator.generate(mockResults);

            expect(result).toContain('fleet-dashboard.html');
        });

        it('should create directory if it does not exist', async () => {
            (fs.existsSync as jest.Mock).mockReturnValue(false);

            await generator.generate(mockResults);

            expect(fs.mkdirSync).toHaveBeenCalledWith('./reports', { recursive: true });
        });
    });

    describe('calculateSummary', () => {
        it('should calculate correct average score', () => {
            const summary = generator.calculateSummary(mockResults);

            // (85 + 72 + 95) / 3 = 84
            expect(summary.averageScore).toBe(84);
        });

        it('should count passing and failing sites', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.totalSites).toBe(3);
            expect(summary.passingCount).toBe(2); // status === 'pass'
            expect(summary.failingCount).toBe(1); // status === 'fail'
        });

        it('should identify worst performing sites', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.worstPerforming.length).toBeGreaterThan(0);
            expect(summary.worstPerforming[0].url).toBe('https://app.example.com');
        });

        it('should identify best performing sites', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.bestPerforming.length).toBeGreaterThan(0);
            expect(summary.bestPerforming[0].url).toBe('https://api.example.com');
        });

        it('should count total critical issues', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.totalCritical).toBe(3); // 1 + 2 + 0
        });

        it('should count total high issues', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.totalHigh).toBe(9); // 3 + 5 + 1
        });

        it('should identify trends when comparison data present', () => {
            const summary = generator.calculateSummary(mockResults);

            if (summary.trends) {
                expect(summary.trends.improving).toBe(1);
                expect(summary.trends.declining).toBe(1);
                // Third result has no comparison, so trends only count sites with comparison data
            }
        });

        it('should handle empty results', () => {
            const summary = generator.calculateSummary([]);

            expect(summary.totalSites).toBe(0);
            expect(summary.averageScore).toBe(0);
            expect(summary.passingCount).toBe(0);
            expect(summary.failingCount).toBe(0);
        });

        it('should group sites by status', () => {
            const summary = generator.calculateSummary(mockResults);

            expect(summary.byStatus.pass.length).toBe(2);
            expect(summary.byStatus.fail.length).toBe(1);
            expect(summary.byStatus.warning.length).toBe(0);
        });
    });

    describe('HTML generation', () => {
        it('should include site data in HTML', async () => {
            await generator.generate(mockResults);

            const htmlCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
            const html = htmlCall[1];

            expect(html).toContain('example.com');
            expect(html).toContain('app.example.com');
            expect(html).toContain('api.example.com');
        });

        it('should include summary statistics', async () => {
            await generator.generate(mockResults);

            const htmlCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
            const html = htmlCall[1];

            expect(html).toContain('84'); // Average score
        });

        it('should include trend indicators when available', async () => {
            await generator.generate(mockResults);

            const htmlCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
            const html = htmlCall[1];

            // Should have trend info in HTML (emoji indicators)
            expect(html).toContain('📈'); // improving indicator
        });
    });

    describe('JSON output', () => {
        it('should include all summary fields', async () => {
            await generator.generate(mockResults);

            const jsonCall = (fs.writeFileSync as jest.Mock).mock.calls[1];
            const json = JSON.parse(jsonCall[1]);

            expect(json.summary).toBeDefined();
            expect(json.summary.totalSites).toBe(3);
            expect(json.summary.averageScore).toBe(84);
            expect(json.summary.passingCount).toBe(2);
            expect(json.summary.failingCount).toBe(1);
        });

        it('should include all site results', async () => {
            await generator.generate(mockResults);

            const jsonCall = (fs.writeFileSync as jest.Mock).mock.calls[1];
            const json = JSON.parse(jsonCall[1]);

            expect(json.sites).toHaveLength(3);
            expect(json.sites[0].url).toBe('https://example.com');
        });

        it('should include timestamp', async () => {
            await generator.generate(mockResults);

            const jsonCall = (fs.writeFileSync as jest.Mock).mock.calls[1];
            const json = JSON.parse(jsonCall[1]);

            expect(json.generatedAt).toBeDefined();
            expect(new Date(json.generatedAt).getTime()).toBeGreaterThan(0);
        });
    });

    describe('edge cases', () => {
        it('should handle single site', () => {
            const singleResult = [mockResults[0]];
            const summary = generator.calculateSummary(singleResult);

            expect(summary.totalSites).toBe(1);
            expect(summary.averageScore).toBe(85);
            expect(summary.bestPerforming[0].url).toBe('https://example.com');
            expect(summary.worstPerforming[0].url).toBe('https://example.com');
        });

        it('should handle sites without comparison data', () => {
            const resultsWithoutComparison: FleetSiteResult[] = [{
                url: 'https://new-site.com',
                domain: 'new-site.com',
                healthScore: 75,
                reportPath: './reports/new-site.com/report.html',
                criticalIssues: 0,
                highIssues: 2,
                status: 'warning',
                scanDuration: 25000,
                timestamp: new Date().toISOString(),
            }];

            const summary = generator.calculateSummary(resultsWithoutComparison);

            expect(summary.totalSites).toBe(1);
            expect(summary.warningCount).toBe(1);
        });

        it('should handle sites without score breakdown', () => {
            const resultsWithoutScores: FleetSiteResult[] = [{
                url: 'https://minimal-site.com',
                domain: 'minimal-site.com',
                healthScore: 80,
                reportPath: './reports/minimal-site.com/report.html',
                criticalIssues: 1,
                highIssues: 3,
                status: 'pass',
            }];

            const summary = generator.calculateSummary(resultsWithoutScores);

            expect(summary.totalSites).toBe(1);
            expect(summary.averageScore).toBe(80);
        });

        it('should handle all passing sites', () => {
            const passingResults: FleetSiteResult[] = mockResults.map(r => ({
                ...r,
                status: 'pass' as const,
            }));

            const summary = generator.calculateSummary(passingResults);

            expect(summary.passingCount).toBe(3);
            expect(summary.failingCount).toBe(0);
        });

        it('should handle all failing sites', () => {
            const failingResults: FleetSiteResult[] = mockResults.map(r => ({
                ...r,
                status: 'fail' as const,
            }));

            const summary = generator.calculateSummary(failingResults);

            expect(summary.passingCount).toBe(0);
            expect(summary.failingCount).toBe(3);
        });

        it('should handle warning status sites', () => {
            const warningResults: FleetSiteResult[] = mockResults.map(r => ({
                ...r,
                status: 'warning' as const,
            }));

            const summary = generator.calculateSummary(warningResults);

            expect(summary.warningCount).toBe(3);
            expect(summary.byStatus.warning.length).toBe(3);
        });
    });

    describe('constructor options', () => {
        it('should use default reports directory', () => {
            const defaultGenerator = new FleetReportGenerator();
            // Constructor should work with defaults
            expect(defaultGenerator).toBeDefined();
        });

        it('should accept custom reports directory', async () => {
            const customGenerator = new FleetReportGenerator('/custom/path');
            await customGenerator.generate(mockResults);

            const htmlCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
            // Use backslash-agnostic check for Windows/Unix paths
            expect(htmlCall[0]).toMatch(/custom.*path.*fleet-dashboard\.html/);
        });
    });
});
