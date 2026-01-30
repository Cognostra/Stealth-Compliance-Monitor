/**
 * Real-Time Dashboard Service
 *
 * Provides real-time dashboard capabilities for monitoring
 * compliance status across multiple sites/scans.
 *
 * Features:
 * - WebSocket-based real-time updates
 * - Dashboard metric aggregation
 * - Trend visualization data
 * - Multi-site status overview
 * - Alert stream
 */

import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface DashboardMetric {
    name: string;
    value: number;
    unit: string;
    timestamp: string;
    trend: 'up' | 'down' | 'stable';
    change?: number;
}

export interface SiteStatus {
    url: string;
    status: 'compliant' | 'warning' | 'violation' | 'scanning' | 'error';
    lastScan: string;
    score: number;
    findings: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    trend: 'improving' | 'stable' | 'degrading';
}

export interface DashboardEvent {
    type: 'finding' | 'scan-complete' | 'alert' | 'status-change';
    severity: 'info' | 'warning' | 'error' | 'critical';
    message: string;
    url?: string;
    timestamp: string;
    data?: unknown;
}

export interface DashboardConfig {
    refreshInterval: number;
    retentionHours: number;
    maxSites: number;
    enableWebSocket: boolean;
    alertThresholds: {
        critical: number;
        high: number;
    };
}

export interface HistoricalDataPoint {
    timestamp: string;
    avgScore: number;
    totalFindings: number;
    sitesScanned: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class RealTimeDashboardService {
    private config: DashboardConfig;
    private siteStatuses: Map<string, SiteStatus> = new Map();
    private metrics: DashboardMetric[] = [];
    private events: DashboardEvent[] = [];
    private historicalData: HistoricalDataPoint[] = [];
    private updateCallbacks: Array<(data: unknown) => void> = [];

    constructor(config?: Partial<DashboardConfig>) {
        this.config = {
            refreshInterval: 5000,
            retentionHours: 24,
            maxSites: 100,
            enableWebSocket: false,
            alertThresholds: { critical: 1, high: 5 },
            ...config,
        };
    }

    /**
     * Register a site for monitoring.
     */
    registerSite(url: string): void {
        if (this.siteStatuses.has(url)) return;

        this.siteStatuses.set(url, {
            url,
            status: 'scanning',
            lastScan: new Date().toISOString(),
            score: 0,
            findings: { critical: 0, high: 0, medium: 0, low: 0 },
            trend: 'stable',
        });

        logger.info(`[Dashboard] Registered site: ${url}`);
    }

    /**
     * Update site status with new scan results.
     */
    updateSiteStatus(url: string, findings: Array<{ severity: string }>): void {
        const existing = this.siteStatuses.get(url);
        const now = new Date().toISOString();

        const counts = {
            critical: findings.filter(f => f.severity === 'critical').length,
            high: findings.filter(f => f.severity === 'high').length,
            medium: findings.filter(f => f.severity === 'medium').length,
            low: findings.filter(f => f.severity === 'low').length,
        };

        let status: SiteStatus['status'] = 'compliant';
        if (counts.critical > 0) status = 'violation';
        else if (counts.high > 0) status = 'warning';
        else if (counts.medium > 0 || counts.low > 0) status = 'compliant';

        // Calculate score (0-100)
        const score = Math.max(0, 100 - (counts.critical * 20 + counts.high * 10 + counts.medium * 3 + counts.low));

        // Determine trend
        let trend: SiteStatus['trend'] = 'stable';
        if (existing) {
            const prevTotal = existing.findings.critical + existing.findings.high;
            const newTotal = counts.critical + counts.high;
            if (newTotal < prevTotal) trend = 'improving';
            else if (newTotal > prevTotal) trend = 'degrading';
        }

        const updated: SiteStatus = {
            url,
            status,
            lastScan: now,
            score,
            findings: counts,
            trend,
        };

        this.siteStatuses.set(url, updated);

        // Emit event
        this.emitEvent({
            type: 'scan-complete',
            severity: counts.critical > 0 ? 'critical' : counts.high > 0 ? 'error' : 'info',
            message: `Scan completed for ${url}: ${findings.length} findings`,
            url,
            timestamp: now,
            data: updated,
        });

        // Check thresholds
        if (counts.critical >= this.config.alertThresholds.critical) {
            this.emitEvent({
                type: 'alert',
                severity: 'critical',
                message: `Critical threshold exceeded: ${counts.critical} critical findings on ${url}`,
                url,
                timestamp: now,
            });
        }
    }

    /**
     * Get current metrics snapshot.
     */
    getMetrics(): DashboardMetric[] {
        const sites = Array.from(this.siteStatuses.values());
        const now = new Date().toISOString();

        const totalSites = sites.length;
        const compliant = sites.filter(s => s.status === 'compliant').length;
        const warnings = sites.filter(s => s.status === 'warning').length;
        const violations = sites.filter(s => s.status === 'violation').length;
        const avgScore = totalSites > 0
            ? sites.reduce((sum, s) => sum + s.score, 0) / totalSites
            : 0;

        const totalFindings = sites.reduce(
            (sum, s) => sum + s.findings.critical + s.findings.high + s.findings.medium + s.findings.low,
            0
        );

        return [
            {
                name: 'total-sites',
                value: totalSites,
                unit: 'sites',
                timestamp: now,
                trend: 'stable',
            },
            {
                name: 'compliance-rate',
                value: totalSites > 0 ? (compliant / totalSites) * 100 : 0,
                unit: 'percent',
                timestamp: now,
                trend: this.calculateTrend('compliance-rate', compliant / totalSites),
            },
            {
                name: 'avg-score',
                value: avgScore,
                unit: 'score',
                timestamp: now,
                trend: this.calculateTrend('avg-score', avgScore),
            },
            {
                name: 'total-findings',
                value: totalFindings,
                unit: 'findings',
                timestamp: now,
                trend: this.calculateTrend('total-findings', totalFindings, true),
            },
            {
                name: 'critical-findings',
                value: sites.reduce((sum, s) => sum + s.findings.critical, 0),
                unit: 'findings',
                timestamp: now,
                trend: this.calculateTrend('critical-findings', totalFindings, true),
            },
            {
                name: 'sites-with-violations',
                value: violations,
                unit: 'sites',
                timestamp: now,
                trend: this.calculateTrend('sites-with-violations', violations, true),
            },
        ];
    }

    /**
     * Get all site statuses.
     */
    getSiteStatuses(): SiteStatus[] {
        return Array.from(this.siteStatuses.values());
    }

    /**
     * Get recent events.
     */
    getEvents(limit: number = 50): DashboardEvent[] {
        return this.events.slice(-limit);
    }

    /**
     * Get historical data for charting.
     */
    getHistoricalData(hours: number = 24): HistoricalDataPoint[] {
        const cutoff = new Date();
        cutoff.setHours(cutoff.getHours() - hours);

        return this.historicalData.filter(d => new Date(d.timestamp) >= cutoff);
    }

    /**
     * Record historical snapshot.
     */
    recordSnapshot(): void {
        const metrics = this.getMetrics();
        const avgScore = metrics.find(m => m.name === 'avg-score')?.value || 0;
        const totalFindings = metrics.find(m => m.name === 'total-findings')?.value || 0;

        this.historicalData.push({
            timestamp: new Date().toISOString(),
            avgScore,
            totalFindings,
            sitesScanned: this.siteStatuses.size,
        });

        // Prune old data
        const cutoff = new Date();
        cutoff.setHours(cutoff.getHours() - this.config.retentionHours);
        this.historicalData = this.historicalData.filter(
            d => new Date(d.timestamp) >= cutoff
        );
    }

    /**
     * Subscribe to real-time updates.
     */
    onUpdate(callback: (data: unknown) => void): () => void {
        this.updateCallbacks.push(callback);
        return () => {
            const index = this.updateCallbacks.indexOf(callback);
            if (index > -1) {
                this.updateCallbacks.splice(index, 1);
            }
        };
    }

    /**
     * Generate dashboard summary for executive view.
     */
    generateExecutiveSummary(): {
        overallHealth: 'excellent' | 'good' | 'fair' | 'poor';
        sitesAtRisk: number;
        complianceTrend: 'improving' | 'stable' | 'degrading';
        keyMetrics: DashboardMetric[];
        topIssues: Array<{ type: string; count: number; sites: string[] }>;
    } {
        const metrics = this.getMetrics();
        const sites = Array.from(this.siteStatuses.values());
        const avgScore = metrics.find(m => m.name === 'avg-score')?.value || 0;

        // Determine overall health
        let overallHealth: 'excellent' | 'good' | 'fair' | 'poor' = 'poor';
        if (avgScore >= 90) overallHealth = 'excellent';
        else if (avgScore >= 75) overallHealth = 'good';
        else if (avgScore >= 50) overallHealth = 'fair';

        // Count sites at risk
        const sitesAtRisk = sites.filter(
            s => s.status === 'violation' || s.findings.critical > 0 || s.findings.high >= 5
        ).length;

        // Determine trend
        const recentHistory = this.historicalData.slice(-5);
        let complianceTrend: 'improving' | 'stable' | 'degrading' = 'stable';
        if (recentHistory.length >= 2) {
            const first = recentHistory[0].avgScore;
            const last = recentHistory[recentHistory.length - 1].avgScore;
            const change = last - first;
            if (change > 5) complianceTrend = 'improving';
            else if (change < -5) complianceTrend = 'degrading';
        }

        // Aggregate top issues (placeholder - would need actual finding types)
        const topIssues = sitesAtRisk > 0
            ? [{ type: 'Critical Security Findings', count: sitesAtRisk, sites: sites.filter(s => s.findings.critical > 0).map(s => s.url) }]
            : [];

        return {
            overallHealth,
            sitesAtRisk,
            complianceTrend,
            keyMetrics: metrics.slice(0, 4),
            topIssues,
        };
    }

    /**
     * Export dashboard data to various formats.
     */
    exportData(format: 'json' | 'csv'): string {
        const sites = this.getSiteStatuses();

        if (format === 'json') {
            return JSON.stringify({
                timestamp: new Date().toISOString(),
                metrics: this.getMetrics(),
                sites,
                events: this.getEvents(100),
            }, null, 2);
        }

        // CSV format
        const headers = 'URL,Status,Score,Critical,High,Medium,Low,Trend,LastScan\n';
        const rows = sites.map(s =>
            `${s.url},${s.status},${s.score},${s.findings.critical},${s.findings.high},${s.findings.medium},${s.findings.low},${s.trend},${s.lastScan}`
        ).join('\n');
        return headers + rows;
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PRIVATE METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private emitEvent(event: DashboardEvent): void {
        this.events.push(event);

        // Prune old events
        const maxEvents = 1000;
        if (this.events.length > maxEvents) {
            this.events = this.events.slice(-maxEvents);
        }

        // Notify subscribers
        for (const callback of this.updateCallbacks) {
            try {
                callback({ type: 'event', data: event });
            } catch {
                // Ignore callback errors
            }
        }
    }

    private calculateTrend(metricName: string, currentValue: number, inverted: boolean = false): DashboardMetric['trend'] {
        // Store previous values for trend calculation
        const key = `trend-${metricName}`;
        const previous = this.getStoredValue(key);

        if (previous === null) {
            this.storeValue(key, currentValue);
            return 'stable';
        }

        const diff = currentValue - previous;
        const threshold = 0.05; // 5% change threshold

        this.storeValue(key, currentValue);

        if (Math.abs(diff) < threshold) return 'stable';

        // For inverted metrics (like findings count), down is good
        if (inverted) {
            return diff < 0 ? 'up' : 'down';
        }

        return diff > 0 ? 'up' : 'down';
    }

    private storedValues: Map<string, number> = new Map();

    private storeValue(key: string, value: number): void {
        this.storedValues.set(key, value);
    }

    private getStoredValue(key: string): number | null {
        return this.storedValues.get(key) ?? null;
    }
}

export default RealTimeDashboardService;
