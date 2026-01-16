/**
 * History Service
 * Tracks historical run data for trend analysis with comprehensive analytics
 */

import * as fs from 'fs';
import * as path from 'path';
import { EnvConfig, getConfig } from '../config/env';
import { logger } from '../utils/logger';

export interface RunSummary {
    timestamp: string;
    targetUrl: string;
    overallScore: number;
    performanceScore: number;
    accessibilityScore: number;
    securityScore: number;
    seoScore?: number;
    metrics: {
        criticalIssues: number;
        highIssues: number;
        mediumIssues?: number;
        lowIssues?: number;
        passed: boolean;
        duration: number;
        pagesVisited: number;
        vulnerableLibraries?: number;
        leakedSecrets?: number;
        a11yViolations?: number;
    };
    profile?: string;
    version?: string;
}

export interface TrendAnalysis {
    /** Number of runs analyzed */
    runsAnalyzed: number;
    /** Average overall score */
    averageScore: number;
    /** Score trend: 'improving' | 'declining' | 'stable' */
    trend: 'improving' | 'declining' | 'stable';
    /** Score change from first to last run */
    scoreChange: number;
    /** Percentage of runs that passed */
    passRate: number;
    /** Average duration in ms */
    averageDuration: number;
    /** Best score achieved */
    bestScore: number;
    /** Worst score achieved */
    worstScore: number;
    /** Issues trend by severity */
    issuesTrend: {
        critical: { average: number; trend: 'increasing' | 'decreasing' | 'stable' };
        high: { average: number; trend: 'increasing' | 'decreasing' | 'stable' };
    };
    /** Score breakdown averages */
    scoreBreakdown: {
        performance: number;
        accessibility: number;
        security: number;
        seo: number;
    };
    /** Weekly comparison (if enough data) */
    weeklyComparison?: {
        thisWeek: number;
        lastWeek: number;
        change: number;
    };
}

export interface ComparisonResult {
    /** Current run */
    current: RunSummary;
    /** Previous run */
    previous: RunSummary | null;
    /** Score difference */
    scoreDiff: number;
    /** New issues introduced */
    newIssues: {
        critical: number;
        high: number;
    };
    /** Issues resolved */
    resolvedIssues: {
        critical: number;
        high: number;
    };
    /** Status: 'improved' | 'regressed' | 'unchanged' */
    status: 'improved' | 'regressed' | 'unchanged';
}

export class HistoryService {
    private config: EnvConfig;
    private historyFile: string;
    private maxRuns: number;

    constructor(maxRuns: number = 100) {
        this.config = getConfig();
        this.maxRuns = maxRuns;
        // Ensure reports dir exists
        if (!fs.existsSync(this.config.REPORTS_DIR)) {
            fs.mkdirSync(this.config.REPORTS_DIR, { recursive: true });
        }
        this.historyFile = path.join(this.config.REPORTS_DIR, 'history.json');
    }

    /**
     * Save the current run summary to history
     */
    saveRun(summary: RunSummary): void {
        try {
            const history = this.getTrendData();

            // Add version and ensure timestamp
            const enrichedSummary: RunSummary = {
                ...summary,
                timestamp: summary.timestamp || new Date().toISOString(),
                version: summary.version || '1.0.0',
            };

            // Add new run
            history.push(enrichedSummary);

            // Keep only last N runs to prevent infinite growth
            while (history.length > this.maxRuns) {
                history.shift(); // Remove oldest
            }

            fs.writeFileSync(this.historyFile, JSON.stringify(history, null, 2));
            logger.info(`Run summary saved to history.json (${history.length} runs stored)`);
        } catch (error) {
            logger.error(`Failed to save history: ${error}`);
        }
    }

    /**
     * Get historical trend data
     */
    getTrendData(): RunSummary[] {
        try {
            if (!fs.existsSync(this.historyFile)) {
                return [];
            }

            const content = fs.readFileSync(this.historyFile, 'utf-8');
            return JSON.parse(content);
        } catch (error) {
            logger.warn(`Failed to load history: ${error}`);
            return [];
        }
    }

    /**
     * Get runs for a specific URL
     */
    getRunsForUrl(targetUrl: string): RunSummary[] {
        const history = this.getTrendData();
        return history.filter(run => run.targetUrl === targetUrl);
    }

    /**
     * Analyze trends across all runs
     */
    analyzeTrends(targetUrl?: string): TrendAnalysis | null {
        let history = this.getTrendData();
        
        if (targetUrl) {
            history = history.filter(run => run.targetUrl === targetUrl);
        }

        if (history.length < 2) {
            return null;
        }

        // Calculate averages
        const scores = history.map(r => r.overallScore);
        const criticalCounts = history.map(r => r.metrics.criticalIssues);
        const highCounts = history.map(r => r.metrics.highIssues);
        const durations = history.map(r => r.metrics.duration);
        const passCount = history.filter(r => r.metrics.passed).length;

        const averageScore = scores.reduce((a, b) => a + b, 0) / scores.length;
        const averageCritical = criticalCounts.reduce((a, b) => a + b, 0) / criticalCounts.length;
        const averageHigh = highCounts.reduce((a, b) => a + b, 0) / highCounts.length;
        const averageDuration = durations.reduce((a, b) => a + b, 0) / durations.length;

        // Calculate trends (compare first half to second half)
        const midpoint = Math.floor(history.length / 2);
        const firstHalfAvg = scores.slice(0, midpoint).reduce((a, b) => a + b, 0) / midpoint;
        const secondHalfAvg = scores.slice(midpoint).reduce((a, b) => a + b, 0) / (scores.length - midpoint);
        
        const firstHalfCritical = criticalCounts.slice(0, midpoint).reduce((a, b) => a + b, 0) / midpoint;
        const secondHalfCritical = criticalCounts.slice(midpoint).reduce((a, b) => a + b, 0) / (criticalCounts.length - midpoint);

        const firstHalfHigh = highCounts.slice(0, midpoint).reduce((a, b) => a + b, 0) / midpoint;
        const secondHalfHigh = highCounts.slice(midpoint).reduce((a, b) => a + b, 0) / (highCounts.length - midpoint);

        // Determine score trend
        let trend: 'improving' | 'declining' | 'stable';
        const scoreDiff = secondHalfAvg - firstHalfAvg;
        if (scoreDiff > 5) {
            trend = 'improving';
        } else if (scoreDiff < -5) {
            trend = 'declining';
        } else {
            trend = 'stable';
        }

        // Determine issues trends
        const criticalTrend: 'increasing' | 'decreasing' | 'stable' = 
            secondHalfCritical > firstHalfCritical + 0.5 ? 'increasing' :
            secondHalfCritical < firstHalfCritical - 0.5 ? 'decreasing' : 'stable';

        const highTrend: 'increasing' | 'decreasing' | 'stable' = 
            secondHalfHigh > firstHalfHigh + 1 ? 'increasing' :
            secondHalfHigh < firstHalfHigh - 1 ? 'decreasing' : 'stable';

        // Score breakdown averages
        const performanceAvg = history.map(r => r.performanceScore).reduce((a, b) => a + b, 0) / history.length;
        const accessibilityAvg = history.map(r => r.accessibilityScore).reduce((a, b) => a + b, 0) / history.length;
        const securityAvg = history.map(r => r.securityScore).reduce((a, b) => a + b, 0) / history.length;
        const seoAvg = history.filter(r => r.seoScore !== undefined).length > 0 
            ? history.filter(r => r.seoScore !== undefined).map(r => r.seoScore!).reduce((a, b) => a + b, 0) / history.filter(r => r.seoScore !== undefined).length
            : 0;

        // Weekly comparison
        let weeklyComparison: TrendAnalysis['weeklyComparison'];
        const now = new Date();
        const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

        const thisWeekRuns = history.filter(r => new Date(r.timestamp) >= oneWeekAgo);
        const lastWeekRuns = history.filter(r => {
            const date = new Date(r.timestamp);
            return date >= twoWeeksAgo && date < oneWeekAgo;
        });

        if (thisWeekRuns.length > 0 && lastWeekRuns.length > 0) {
            const thisWeekAvg = thisWeekRuns.map(r => r.overallScore).reduce((a, b) => a + b, 0) / thisWeekRuns.length;
            const lastWeekAvg = lastWeekRuns.map(r => r.overallScore).reduce((a, b) => a + b, 0) / lastWeekRuns.length;
            weeklyComparison = {
                thisWeek: Math.round(thisWeekAvg),
                lastWeek: Math.round(lastWeekAvg),
                change: Math.round(thisWeekAvg - lastWeekAvg),
            };
        }

        return {
            runsAnalyzed: history.length,
            averageScore: Math.round(averageScore),
            trend,
            scoreChange: Math.round(scores[scores.length - 1] - scores[0]),
            passRate: Math.round((passCount / history.length) * 100),
            averageDuration: Math.round(averageDuration),
            bestScore: Math.max(...scores),
            worstScore: Math.min(...scores),
            issuesTrend: {
                critical: { average: Math.round(averageCritical * 10) / 10, trend: criticalTrend },
                high: { average: Math.round(averageHigh * 10) / 10, trend: highTrend },
            },
            scoreBreakdown: {
                performance: Math.round(performanceAvg),
                accessibility: Math.round(accessibilityAvg),
                security: Math.round(securityAvg),
                seo: Math.round(seoAvg),
            },
            weeklyComparison,
        };
    }

    /**
     * Compare current run with previous
     */
    compareWithPrevious(current: RunSummary): ComparisonResult {
        const history = this.getRunsForUrl(current.targetUrl);
        const previous = history.length > 0 ? history[history.length - 1] : null;

        const scoreDiff = previous ? current.overallScore - previous.overallScore : 0;

        const newCritical = previous ? Math.max(0, current.metrics.criticalIssues - previous.metrics.criticalIssues) : current.metrics.criticalIssues;
        const newHigh = previous ? Math.max(0, current.metrics.highIssues - previous.metrics.highIssues) : current.metrics.highIssues;

        const resolvedCritical = previous ? Math.max(0, previous.metrics.criticalIssues - current.metrics.criticalIssues) : 0;
        const resolvedHigh = previous ? Math.max(0, previous.metrics.highIssues - current.metrics.highIssues) : 0;

        let status: 'improved' | 'regressed' | 'unchanged';
        if (!previous) {
            status = 'unchanged';
        } else if (scoreDiff > 3 || (resolvedCritical > 0 && newCritical === 0)) {
            status = 'improved';
        } else if (scoreDiff < -3 || newCritical > 0) {
            status = 'regressed';
        } else {
            status = 'unchanged';
        }

        return {
            current,
            previous,
            scoreDiff,
            newIssues: { critical: newCritical, high: newHigh },
            resolvedIssues: { critical: resolvedCritical, high: resolvedHigh },
            status,
        };
    }

    /**
     * Get runs from the last N days
     */
    getRecentRuns(days: number, targetUrl?: string): RunSummary[] {
        const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        let history = this.getTrendData();
        
        if (targetUrl) {
            history = history.filter(run => run.targetUrl === targetUrl);
        }

        return history.filter(run => new Date(run.timestamp) >= cutoff);
    }

    /**
     * Generate a text summary of trends
     */
    generateTrendReport(targetUrl?: string): string {
        const analysis = this.analyzeTrends(targetUrl);
        
        if (!analysis) {
            return 'Insufficient data for trend analysis. At least 2 runs are required.';
        }

        const lines: string[] = [
            '═══════════════════════════════════════════════════════════════',
            '                    📊 TREND ANALYSIS REPORT                    ',
            '═══════════════════════════════════════════════════════════════',
            '',
            `📈 Runs Analyzed: ${analysis.runsAnalyzed}`,
            `📊 Average Score: ${analysis.averageScore}/100`,
            `📉 Score Trend: ${analysis.trend.toUpperCase()} (${analysis.scoreChange >= 0 ? '+' : ''}${analysis.scoreChange} points)`,
            `✅ Pass Rate: ${analysis.passRate}%`,
            `⏱️  Average Duration: ${(analysis.averageDuration / 1000).toFixed(1)}s`,
            '',
            '── Score Breakdown ──',
            `  Performance:   ${analysis.scoreBreakdown.performance}/100`,
            `  Accessibility: ${analysis.scoreBreakdown.accessibility}/100`,
            `  Security:      ${analysis.scoreBreakdown.security}/100`,
            `  SEO:           ${analysis.scoreBreakdown.seo}/100`,
            '',
            '── Issues Trend ──',
            `  Critical: ${analysis.issuesTrend.critical.average} avg (${analysis.issuesTrend.critical.trend})`,
            `  High: ${analysis.issuesTrend.high.average} avg (${analysis.issuesTrend.high.trend})`,
            '',
            `🏆 Best Score: ${analysis.bestScore}`,
            `⚠️  Worst Score: ${analysis.worstScore}`,
        ];

        if (analysis.weeklyComparison) {
            lines.push('');
            lines.push('── Weekly Comparison ──');
            lines.push(`  This Week: ${analysis.weeklyComparison.thisWeek}`);
            lines.push(`  Last Week: ${analysis.weeklyComparison.lastWeek}`);
            lines.push(`  Change: ${analysis.weeklyComparison.change >= 0 ? '+' : ''}${analysis.weeklyComparison.change}`);
        }

        lines.push('');
        lines.push('═══════════════════════════════════════════════════════════════');

        return lines.join('\n');
    }

    /**
     * Export history to CSV
     */
    exportToCsv(outputPath?: string): string {
        const history = this.getTrendData();
        
        if (history.length === 0) {
            throw new Error('No history data to export');
        }

        const headers = [
            'Timestamp',
            'Target URL',
            'Overall Score',
            'Performance',
            'Accessibility',
            'Security',
            'SEO',
            'Critical Issues',
            'High Issues',
            'Passed',
            'Duration (ms)',
            'Pages Visited',
        ];

        const rows = history.map(run => [
            run.timestamp,
            run.targetUrl,
            run.overallScore,
            run.performanceScore,
            run.accessibilityScore,
            run.securityScore,
            run.seoScore || '',
            run.metrics.criticalIssues,
            run.metrics.highIssues,
            run.metrics.passed ? 'Yes' : 'No',
            run.metrics.duration,
            run.metrics.pagesVisited,
        ]);

        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

        const filePath = outputPath || path.join(this.config.REPORTS_DIR, 'history-export.csv');
        fs.writeFileSync(filePath, csv);
        
        logger.info(`History exported to ${filePath}`);
        return filePath;
    }

    /**
     * Clear history (for testing or reset)
     */
    clearHistory(): void {
        if (fs.existsSync(this.historyFile)) {
            fs.unlinkSync(this.historyFile);
            logger.info('History cleared');
        }
    }
}
