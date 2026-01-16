/**
 * History Service Tests
 */

import { jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import { HistoryService, RunSummary, TrendAnalysis } from '../../src/services/HistoryService.js';

// Mock fs module
jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

// Mock config
jest.mock('../../src/config/env.js', () => ({
    getConfig: () => ({
        REPORTS_DIR: './test-reports',
    }),
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

describe('HistoryService', () => {
    let service: HistoryService;
    const testReportsDir = './test-reports';
    const historyFilePath = path.join(testReportsDir, 'history.json');

    beforeEach(() => {
        jest.clearAllMocks();
        mockFs.existsSync.mockReturnValue(true);
        service = new HistoryService(50);
    });

    describe('constructor', () => {
        it('should create reports directory if it does not exist', () => {
            mockFs.existsSync.mockReturnValue(false);
            mockFs.mkdirSync.mockReturnValue(undefined);

            new HistoryService();

            expect(mockFs.mkdirSync).toHaveBeenCalledWith(testReportsDir, { recursive: true });
        });

        it('should not create directory if it exists', () => {
            mockFs.existsSync.mockReturnValue(true);

            new HistoryService();

            expect(mockFs.mkdirSync).not.toHaveBeenCalled();
        });
    });

    describe('saveRun', () => {
        const mockSummary: RunSummary = {
            timestamp: '2026-01-16T10:00:00Z',
            targetUrl: 'https://example.com',
            overallScore: 85,
            performanceScore: 90,
            accessibilityScore: 80,
            securityScore: 85,
            metrics: {
                criticalIssues: 1,
                highIssues: 3,
                passed: true,
                duration: 30000,
                pagesVisited: 10,
            },
        };

        it('should save a run summary to history', () => {
            mockFs.existsSync.mockReturnValue(false);
            mockFs.readFileSync.mockReturnValue('[]');
            mockFs.writeFileSync.mockReturnValue(undefined);

            service.saveRun(mockSummary);

            expect(mockFs.writeFileSync).toHaveBeenCalled();
            const writeCall = mockFs.writeFileSync.mock.calls[0];
            const savedData = JSON.parse(writeCall[1] as string);
            expect(savedData).toHaveLength(1);
            expect(savedData[0].targetUrl).toBe('https://example.com');
        });

        it('should append to existing history', () => {
            const existingHistory = JSON.stringify([
                { ...mockSummary, timestamp: '2026-01-15T10:00:00Z' },
            ]);
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(existingHistory);
            mockFs.writeFileSync.mockReturnValue(undefined);

            service.saveRun(mockSummary);

            const writeCall = mockFs.writeFileSync.mock.calls[0];
            const savedData = JSON.parse(writeCall[1] as string);
            expect(savedData).toHaveLength(2);
        });

        it('should limit history to maxRuns', () => {
            const existingHistory = Array(50).fill(0).map((_, i) => ({
                ...mockSummary,
                timestamp: `2026-01-${String(i + 1).padStart(2, '0')}T10:00:00Z`,
            }));
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(existingHistory));
            mockFs.writeFileSync.mockReturnValue(undefined);

            service.saveRun(mockSummary);

            const writeCall = mockFs.writeFileSync.mock.calls[0];
            const savedData = JSON.parse(writeCall[1] as string);
            expect(savedData).toHaveLength(50); // Should not exceed maxRuns
        });
    });

    describe('getTrendData', () => {
        it('should return empty array if file does not exist', () => {
            mockFs.existsSync.mockReturnValue(false);

            const result = service.getTrendData();

            expect(result).toEqual([]);
        });

        it('should return parsed history data', () => {
            const mockData: RunSummary[] = [
                {
                    timestamp: '2026-01-16T10:00:00Z',
                    targetUrl: 'https://example.com',
                    overallScore: 85,
                    performanceScore: 90,
                    accessibilityScore: 80,
                    securityScore: 85,
                    metrics: {
                        criticalIssues: 1,
                        highIssues: 3,
                        passed: true,
                        duration: 30000,
                        pagesVisited: 10,
                    },
                },
            ];
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(mockData));

            const result = service.getTrendData();

            expect(result).toEqual(mockData);
        });

        it('should return empty array on parse error', () => {
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue('invalid json');

            const result = service.getTrendData();

            expect(result).toEqual([]);
        });
    });

    describe('analyzeTrends', () => {
        const generateHistory = (count: number, baseScore: number = 80): RunSummary[] => {
            return Array(count).fill(0).map((_, i) => ({
                timestamp: new Date(Date.now() - (count - i) * 24 * 60 * 60 * 1000).toISOString(),
                targetUrl: 'https://example.com',
                overallScore: baseScore + (i % 10) - 5, // Varying scores
                performanceScore: 85,
                accessibilityScore: 80,
                securityScore: 75,
                seoScore: 90,
                metrics: {
                    criticalIssues: i % 3,
                    highIssues: i % 5,
                    passed: i % 3 !== 0,
                    duration: 30000,
                    pagesVisited: 10,
                },
            }));
        };

        it('should return null if insufficient data', () => {
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify([{ overallScore: 80 }]));

            const result = service.analyzeTrends();

            expect(result).toBeNull();
        });

        it('should calculate trend analysis', () => {
            const history = generateHistory(10);
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));

            const result = service.analyzeTrends();

            expect(result).not.toBeNull();
            expect(result!.runsAnalyzed).toBe(10);
            expect(result!.averageScore).toBeGreaterThan(0);
            expect(['improving', 'declining', 'stable']).toContain(result!.trend);
            expect(result!.passRate).toBeGreaterThanOrEqual(0);
            expect(result!.passRate).toBeLessThanOrEqual(100);
        });

        it('should calculate improving trend', () => {
            const history = Array(10).fill(0).map((_, i) => ({
                timestamp: new Date(Date.now() - (10 - i) * 24 * 60 * 60 * 1000).toISOString(),
                targetUrl: 'https://example.com',
                overallScore: 50 + i * 5, // 50 -> 95, clearly improving
                performanceScore: 85,
                accessibilityScore: 80,
                securityScore: 75,
                metrics: {
                    criticalIssues: 0,
                    highIssues: 0,
                    passed: true,
                    duration: 30000,
                    pagesVisited: 10,
                },
            }));
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));

            const result = service.analyzeTrends();

            expect(result!.trend).toBe('improving');
        });

        it('should calculate declining trend', () => {
            const history = Array(10).fill(0).map((_, i) => ({
                timestamp: new Date(Date.now() - (10 - i) * 24 * 60 * 60 * 1000).toISOString(),
                targetUrl: 'https://example.com',
                overallScore: 95 - i * 5, // 95 -> 50, clearly declining
                performanceScore: 85,
                accessibilityScore: 80,
                securityScore: 75,
                metrics: {
                    criticalIssues: 0,
                    highIssues: 0,
                    passed: true,
                    duration: 30000,
                    pagesVisited: 10,
                },
            }));
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));

            const result = service.analyzeTrends();

            expect(result!.trend).toBe('declining');
        });

        it('should filter by target URL', () => {
            const history = [
                {
                    timestamp: '2026-01-15T10:00:00Z',
                    targetUrl: 'https://example.com',
                    overallScore: 80,
                    performanceScore: 85,
                    accessibilityScore: 80,
                    securityScore: 75,
                    metrics: { criticalIssues: 0, highIssues: 0, passed: true, duration: 30000, pagesVisited: 10 },
                },
                {
                    timestamp: '2026-01-16T10:00:00Z',
                    targetUrl: 'https://example.com',
                    overallScore: 85,
                    performanceScore: 85,
                    accessibilityScore: 80,
                    securityScore: 75,
                    metrics: { criticalIssues: 0, highIssues: 0, passed: true, duration: 30000, pagesVisited: 10 },
                },
                {
                    timestamp: '2026-01-16T10:00:00Z',
                    targetUrl: 'https://other.com',
                    overallScore: 90,
                    performanceScore: 85,
                    accessibilityScore: 80,
                    securityScore: 75,
                    metrics: { criticalIssues: 0, highIssues: 0, passed: true, duration: 30000, pagesVisited: 10 },
                },
            ];
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));

            const result = service.analyzeTrends('https://example.com');

            expect(result).not.toBeNull();
            expect(result!.runsAnalyzed).toBe(2);
        });
    });

    describe('compareWithPrevious', () => {
        it('should compare current run with previous', () => {
            const previous: RunSummary = {
                timestamp: '2026-01-15T10:00:00Z',
                targetUrl: 'https://example.com',
                overallScore: 75,
                performanceScore: 80,
                accessibilityScore: 70,
                securityScore: 75,
                metrics: {
                    criticalIssues: 2,
                    highIssues: 5,
                    passed: false,
                    duration: 30000,
                    pagesVisited: 10,
                },
            };
            const current: RunSummary = {
                timestamp: '2026-01-16T10:00:00Z',
                targetUrl: 'https://example.com',
                overallScore: 85,
                performanceScore: 90,
                accessibilityScore: 80,
                securityScore: 85,
                metrics: {
                    criticalIssues: 0,
                    highIssues: 2,
                    passed: true,
                    duration: 25000,
                    pagesVisited: 12,
                },
            };
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify([previous]));

            const result = service.compareWithPrevious(current);

            expect(result.current).toEqual(current);
            expect(result.previous).toEqual(previous);
            expect(result.scoreDiff).toBe(10);
            expect(result.status).toBe('improved');
            expect(result.resolvedIssues.critical).toBe(2);
        });

        it('should handle no previous run', () => {
            const current: RunSummary = {
                timestamp: '2026-01-16T10:00:00Z',
                targetUrl: 'https://newsite.com',
                overallScore: 85,
                performanceScore: 90,
                accessibilityScore: 80,
                securityScore: 85,
                metrics: {
                    criticalIssues: 1,
                    highIssues: 2,
                    passed: true,
                    duration: 25000,
                    pagesVisited: 12,
                },
            };
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue('[]');

            const result = service.compareWithPrevious(current);

            expect(result.previous).toBeNull();
            expect(result.scoreDiff).toBe(0);
            expect(result.status).toBe('unchanged');
        });

        it('should detect regression', () => {
            const previous: RunSummary = {
                timestamp: '2026-01-15T10:00:00Z',
                targetUrl: 'https://example.com',
                overallScore: 90,
                performanceScore: 90,
                accessibilityScore: 90,
                securityScore: 90,
                metrics: {
                    criticalIssues: 0,
                    highIssues: 1,
                    passed: true,
                    duration: 30000,
                    pagesVisited: 10,
                },
            };
            const current: RunSummary = {
                timestamp: '2026-01-16T10:00:00Z',
                targetUrl: 'https://example.com',
                overallScore: 70,
                performanceScore: 70,
                accessibilityScore: 70,
                securityScore: 70,
                metrics: {
                    criticalIssues: 3,
                    highIssues: 5,
                    passed: false,
                    duration: 30000,
                    pagesVisited: 10,
                },
            };
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify([previous]));

            const result = service.compareWithPrevious(current);

            expect(result.status).toBe('regressed');
            expect(result.newIssues.critical).toBe(3);
        });
    });

    describe('generateTrendReport', () => {
        it('should generate text report', () => {
            const history = Array(5).fill(0).map((_, i) => ({
                timestamp: new Date(Date.now() - (5 - i) * 24 * 60 * 60 * 1000).toISOString(),
                targetUrl: 'https://example.com',
                overallScore: 80 + i,
                performanceScore: 85,
                accessibilityScore: 80,
                securityScore: 75,
                seoScore: 90,
                metrics: {
                    criticalIssues: 0,
                    highIssues: i,
                    passed: true,
                    duration: 30000,
                    pagesVisited: 10,
                },
            }));
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));

            const report = service.generateTrendReport();

            expect(report).toContain('TREND ANALYSIS REPORT');
            expect(report).toContain('Runs Analyzed: 5');
            expect(report).toContain('Pass Rate:');
        });

        it('should return message for insufficient data', () => {
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue('[]');

            const report = service.generateTrendReport();

            expect(report).toContain('Insufficient data');
        });
    });

    describe('exportToCsv', () => {
        it('should export history to CSV', () => {
            const history: RunSummary[] = [
                {
                    timestamp: '2026-01-16T10:00:00Z',
                    targetUrl: 'https://example.com',
                    overallScore: 85,
                    performanceScore: 90,
                    accessibilityScore: 80,
                    securityScore: 85,
                    seoScore: 88,
                    metrics: {
                        criticalIssues: 1,
                        highIssues: 3,
                        passed: true,
                        duration: 30000,
                        pagesVisited: 10,
                    },
                },
            ];
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(history));
            mockFs.writeFileSync.mockReturnValue(undefined);

            const outputPath = service.exportToCsv();

            expect(mockFs.writeFileSync).toHaveBeenCalled();
            const writeCall = mockFs.writeFileSync.mock.calls[0];
            expect(writeCall[1]).toContain('Timestamp,Target URL');
            expect(writeCall[1]).toContain('https://example.com');
        });

        it('should throw error if no history', () => {
            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue('[]');

            expect(() => service.exportToCsv()).toThrow('No history data to export');
        });
    });

    describe('clearHistory', () => {
        it('should delete history file', () => {
            mockFs.existsSync.mockReturnValue(true);
            mockFs.unlinkSync.mockReturnValue(undefined);

            service.clearHistory();

            expect(mockFs.unlinkSync).toHaveBeenCalled();
        });

        it('should not throw if file does not exist', () => {
            mockFs.existsSync.mockReturnValue(false);

            expect(() => service.clearHistory()).not.toThrow();
        });
    });
});
