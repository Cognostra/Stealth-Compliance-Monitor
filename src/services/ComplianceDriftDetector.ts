/**
 * Compliance Drift Detection Service
 *
 * Detects when a site deviates from its established compliance baseline,
 * flagging new violations, removed controls, or configuration changes.
 *
 * Features:
 * - Baseline comparison
 * - Drift categorization (new, removed, changed)
 * - Trend analysis
 * - Alert generation
 * - Historical tracking
 */

import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ComplianceBaseline {
    url: string;
    timestamp: string;
    checks: Array<{
        id: string;
        type: string;
        status: 'pass' | 'fail' | 'warn';
        details: string;
        hash: string; // Content hash for comparison
    }>;
    metadata: {
        scanVersion: string;
        profile: string;
        duration: number;
    };
}

export interface DriftFinding {
    type: 'new_violation' | 'resolved_violation' | 'worsened' | 'improved' | 'changed';
    checkId: string;
    checkType: string;
    previousStatus: 'pass' | 'fail' | 'warn' | null;
    currentStatus: 'pass' | 'fail' | 'warn';
    previousDetails: string | null;
    currentDetails: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    timestamp: string;
}

export interface DriftReport {
    url: string;
    baselineDate: string;
    currentDate: string;
    findings: DriftFinding[];
    summary: {
        newViolations: number;
        resolvedViolations: number;
        worsened: number;
        improved: number;
        unchanged: number;
        totalDrift: number;
    };
    trend: 'improving' | 'stable' | 'degrading' | 'critical';
}

export interface DriftConfig {
    failOnNewViolations: boolean;
    alertThreshold: number; // Number of new violations to trigger alert
    ignoreResolved: boolean;
    trackImprovements: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class ComplianceDriftDetector {
    private config: DriftConfig;
    private baselineStorage: Map<string, ComplianceBaseline> = new Map();

    constructor(config?: Partial<DriftConfig>) {
        this.config = {
            failOnNewViolations: true,
            alertThreshold: 1,
            ignoreResolved: false,
            trackImprovements: true,
            ...config,
        };
    }

    /**
     * Set or update the baseline for a URL.
     */
    setBaseline(url: string, baseline: ComplianceBaseline): void {
        this.baselineStorage.set(this.normalizeUrl(url), baseline);
        logger.info(`[DriftDetector] Set baseline for ${url} with ${baseline.checks.length} checks`);
    }

    /**
     * Get the stored baseline for a URL.
     */
    getBaseline(url: string): ComplianceBaseline | undefined {
        return this.baselineStorage.get(this.normalizeUrl(url));
    }

    /**
     * Compare current scan results against baseline.
     */
    detectDrift(current: ComplianceBaseline): DriftReport {
        const url = this.normalizeUrl(current.url);
        const baseline = this.baselineStorage.get(url);

        if (!baseline) {
            logger.warn(`[DriftDetector] No baseline found for ${url}, using current as baseline`);
            this.setBaseline(url, current);
            return {
                url: current.url,
                baselineDate: current.timestamp,
                currentDate: current.timestamp,
                findings: [],
                summary: {
                    newViolations: 0,
                    resolvedViolations: 0,
                    worsened: 0,
                    improved: 0,
                    unchanged: 0,
                    totalDrift: 0,
                },
                trend: 'stable',
            };
        }

        const findings: DriftFinding[] = [];
        const baselineMap = new Map(baseline.checks.map(c => [c.id, c]));
        const currentMap = new Map(current.checks.map(c => [c.id, c]));

        // Detect new violations (in current but not in baseline or changed from pass)
        for (const [id, currentCheck] of currentMap) {
            const baselineCheck = baselineMap.get(id);

            if (!baselineCheck) {
                // New check or new violation
                if (currentCheck.status === 'fail') {
                    findings.push({
                        type: 'new_violation',
                        checkId: id,
                        checkType: currentCheck.type,
                        previousStatus: null,
                        currentStatus: currentCheck.status,
                        previousDetails: null,
                        currentDetails: currentCheck.details,
                        severity: 'high',
                        timestamp: current.timestamp,
                    });
                }
            } else if (baselineCheck.status !== currentCheck.status) {
                // Status changed
                if (baselineCheck.status === 'pass' && currentCheck.status === 'fail') {
                    findings.push({
                        type: 'new_violation',
                        checkId: id,
                        checkType: currentCheck.type,
                        previousStatus: baselineCheck.status,
                        currentStatus: currentCheck.status,
                        previousDetails: baselineCheck.details,
                        currentDetails: currentCheck.details,
                        severity: 'critical',
                        timestamp: current.timestamp,
                    });
                } else if (baselineCheck.status === 'fail' && currentCheck.status === 'pass') {
                    if (!this.config.ignoreResolved) {
                        findings.push({
                            type: 'resolved_violation',
                            checkId: id,
                            checkType: currentCheck.type,
                            previousStatus: baselineCheck.status,
                            currentStatus: currentCheck.status,
                            previousDetails: baselineCheck.details,
                            currentDetails: currentCheck.details,
                            severity: 'low',
                            timestamp: current.timestamp,
                        });
                    }
                } else if (this.config.trackImprovements) {
                    // Warn to pass or fail to warn
                    const improving = (baselineCheck.status === 'fail' && currentCheck.status === 'warn') ||
                        (baselineCheck.status === 'warn' && currentCheck.status === 'pass');

                    findings.push({
                        type: improving ? 'improved' : 'worsened',
                        checkId: id,
                        checkType: currentCheck.type,
                        previousStatus: baselineCheck.status,
                        currentStatus: currentCheck.status,
                        previousDetails: baselineCheck.details,
                        currentDetails: currentCheck.details,
                        severity: improving ? 'low' : 'medium',
                        timestamp: current.timestamp,
                    });
                }
            } else if (baselineCheck.status === 'fail' && baselineCheck.hash !== currentCheck.hash) {
                // Same status but details changed
                findings.push({
                    type: 'changed',
                    checkId: id,
                    checkType: currentCheck.type,
                    previousStatus: baselineCheck.status,
                    currentStatus: currentCheck.status,
                    previousDetails: baselineCheck.details,
                    currentDetails: currentCheck.details,
                    severity: 'medium',
                    timestamp: current.timestamp,
                });
            }
        }

        // Detect removed checks (in baseline but not in current)
        for (const [id, baselineCheck] of baselineMap) {
            if (!currentMap.has(id) && baselineCheck.status === 'fail') {
                findings.push({
                    type: 'resolved_violation',
                    checkId: id,
                    checkType: baselineCheck.type,
                    previousStatus: baselineCheck.status,
                    currentStatus: 'pass',
                    previousDetails: baselineCheck.details,
                    currentDetails: 'Check no longer present',
                    severity: 'low',
                    timestamp: current.timestamp,
                });
            }
        }

        const summary = this.calculateSummary(findings);
        const trend = this.determineTrend(summary);

        logger.info(`[DriftDetector] Detected ${findings.length} drift items for ${url} (${trend})`);

        return {
            url: current.url,
            baselineDate: baseline.timestamp,
            currentDate: current.timestamp,
            findings,
            summary,
            trend,
        };
    }

    /**
     * Check if drift exceeds alert threshold.
     */
    shouldAlert(report: DriftReport): { alert: boolean; reason: string } {
        if (this.config.failOnNewViolations && report.summary.newViolations > 0) {
            return { alert: true, reason: `${report.summary.newViolations} new violations detected` };
        }

        if (report.summary.newViolations >= this.config.alertThreshold) {
            return { alert: true, reason: `New violations (${report.summary.newViolations}) exceed threshold (${this.config.alertThreshold})` };
        }

        if (report.trend === 'critical') {
            return { alert: true, reason: 'Critical drift trend detected' };
        }

        return { alert: false, reason: 'No alert conditions met' };
    }

    /**
     * Update baseline after accepting current state.
     */
    acceptCurrentAsBaseline(report: DriftReport, current: ComplianceBaseline): void {
        this.setBaseline(report.url, current);
        logger.info(`[DriftDetector] Accepted current state as new baseline for ${report.url}`);
    }

    /**
     * Generate drift trend over multiple scans.
     */
    generateTrend(
        url: string,
        history: ComplianceBaseline[],
        windowSize: number = 5
    ): Array<{ period: string; driftScore: number; trend: string }> {
        const normalizedUrl = this.normalizeUrl(url);
        const recentHistory = history.slice(-windowSize);
        const trends: Array<{ period: string; driftScore: number; trend: string }> = [];

        for (let i = 1; i < recentHistory.length; i++) {
            this.setBaseline(normalizedUrl, recentHistory[i - 1]);
            const report = this.detectDrift(recentHistory[i]);

            trends.push({
                period: `${recentHistory[i - 1].timestamp} → ${recentHistory[i].timestamp}`,
                driftScore: report.summary.totalDrift,
                trend: report.trend,
            });
        }

        return trends;
    }

    /**
     * Export drift report to various formats.
     */
    exportReport(report: DriftReport, format: 'json' | 'markdown' | 'html'): string {
        switch (format) {
            case 'json':
                return JSON.stringify(report, null, 2);

            case 'markdown':
                return this.generateMarkdownReport(report);

            case 'html':
                return this.generateHtmlReport(report);

            default:
                return JSON.stringify(report);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PRIVATE METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private normalizeUrl(url: string): string {
        return url.replace(/\/$/, '').toLowerCase();
    }

    private calculateSummary(findings: DriftFinding[]): DriftReport['summary'] {
        return {
            newViolations: findings.filter(f => f.type === 'new_violation').length,
            resolvedViolations: findings.filter(f => f.type === 'resolved_violation').length,
            worsened: findings.filter(f => f.type === 'worsened').length,
            improved: findings.filter(f => f.type === 'improved').length,
            unchanged: 0, // Would need to calculate separately
            totalDrift: findings.length,
        };
    }

    private determineTrend(summary: DriftReport['summary']): DriftReport['trend'] {
        const improvementScore = summary.resolvedViolations + summary.improved;
        const degradationScore = summary.newViolations * 2 + summary.worsened;

        if (degradationScore === 0 && improvementScore > 0) return 'improving';
        if (summary.newViolations >= 3) return 'critical';
        if (degradationScore > improvementScore) return 'degrading';
        return 'stable';
    }

    private generateMarkdownReport(report: DriftReport): string {
        const lines = [
            '# Compliance Drift Report',
            '',
            `**URL:** ${report.url}`,
            `**Baseline:** ${report.baselineDate}`,
            `**Current:** ${report.currentDate}`,
            `**Trend:** ${report.trend.toUpperCase()}`,
            '',
            '## Summary',
            '',
            `- New Violations: ${report.summary.newViolations}`,
            `- Resolved Violations: ${report.summary.resolvedViolations}`,
            `- Worsened: ${report.summary.worsened}`,
            `- Improved: ${report.summary.improved}`,
            `- Total Drift: ${report.summary.totalDrift}`,
            '',
            '## Findings',
            '',
        ];

        for (const finding of report.findings) {
            lines.push(`### ${finding.checkType} (${finding.type})`);
            lines.push(`- **Severity:** ${finding.severity}`);
            lines.push(`- **Status:** ${finding.previousStatus} → ${finding.currentStatus}`);
            lines.push(`- **Details:** ${finding.currentDetails}`);
            lines.push('');
        }

        return lines.join('\n');
    }

    private generateHtmlReport(report: DriftReport): string {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Drift Report</title>
    <style>
        body { font-family: sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; margin-bottom: 20px; }
        .finding { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .critical { border-left: 4px solid #d32f2f; }
        .high { border-left: 4px solid #f57c00; }
        .medium { border-left: 4px solid #fbc02d; }
        .low { border-left: 4px solid #388e3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Drift Report</h1>
        <p><strong>URL:</strong> ${report.url}</p>
        <p><strong>Trend:</strong> ${report.trend}</p>
        <p><strong>Total Drift:</strong> ${report.summary.totalDrift}</p>
    </div>
    ${report.findings.map(f => `
        <div class="finding ${f.severity}">
            <h3>${f.checkType}</h3>
            <p><strong>Type:</strong> ${f.type}</p>
            <p><strong>Status:</strong> ${f.previousStatus} → ${f.currentStatus}</p>
            <p><strong>Details:</strong> ${f.currentDetails}</p>
        </div>
    `).join('')}
</body>
</html>`;
    }
}

export default ComplianceDriftDetector;
