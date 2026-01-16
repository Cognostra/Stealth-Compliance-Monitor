import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

export interface FleetSiteResult {
    url: string;
    domain: string;
    healthScore: number;
    reportPath: string;
    criticalIssues: number;
    highIssues?: number;
    status: 'pass' | 'fail' | 'warning';
    scanDuration?: number;
    timestamp?: string;
    scores?: {
        performance?: number;
        accessibility?: number;
        security?: number;
        seo?: number;
    };
    comparison?: {
        previousScore: number;
        trend: 'improving' | 'declining' | 'stable';
    };
}

export interface FleetSummary {
    totalSites: number;
    averageScore: number;
    passingCount: number;
    failingCount: number;
    warningCount: number;
    totalCritical: number;
    totalHigh: number;
    worstPerforming: FleetSiteResult[];
    bestPerforming: FleetSiteResult[];
    byStatus: {
        pass: FleetSiteResult[];
        fail: FleetSiteResult[];
        warning: FleetSiteResult[];
    };
    trends?: {
        improving: number;
        declining: number;
        stable: number;
    };
}

export class FleetReportGenerator {
    private reportsDir: string;

    constructor(reportsDir: string = './reports') {
        this.reportsDir = reportsDir;
    }

    /**
     * Generate fleet dashboard from scan results
     */
    async generate(results: FleetSiteResult[]): Promise<string> {
        logger.info(`Generating Fleet Dashboard for ${results.length} sites...`);

        const summary = this.calculateSummary(results);
        const html = this.buildHtml(results, summary);
        const outputPath = path.join(this.reportsDir, 'fleet-dashboard.html');

        // Ensure directory exists
        if (!fs.existsSync(this.reportsDir)) {
            fs.mkdirSync(this.reportsDir, { recursive: true });
        }

        fs.writeFileSync(outputPath, html, 'utf-8');
        logger.info(`Fleet Dashboard generated at: ${outputPath}`);

        // Also generate JSON summary
        const jsonPath = path.join(this.reportsDir, 'fleet-summary.json');
        fs.writeFileSync(jsonPath, JSON.stringify({
            generatedAt: new Date().toISOString(),
            summary,
            sites: results,
        }, null, 2));

        return outputPath;
    }

    /**
     * Calculate fleet-wide summary statistics
     */
    calculateSummary(results: FleetSiteResult[]): FleetSummary {
        const scores = results.map(r => r.healthScore);
        const averageScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) || 0;

        const passingCount = results.filter(r => r.status === 'pass').length;
        const failingCount = results.filter(r => r.status === 'fail').length;
        const warningCount = results.filter(r => r.status === 'warning').length;

        const totalCritical = results.reduce((acc, r) => acc + r.criticalIssues, 0);
        const totalHigh = results.reduce((acc, r) => acc + (r.highIssues || 0), 0);

        // Sort for best/worst
        const sorted = [...results].sort((a, b) => a.healthScore - b.healthScore);
        const worstPerforming = sorted.slice(0, 3);
        const bestPerforming = sorted.slice(-3).reverse();

        // Group by status
        const byStatus = {
            pass: results.filter(r => r.status === 'pass'),
            fail: results.filter(r => r.status === 'fail'),
            warning: results.filter(r => r.status === 'warning'),
        };

        // Calculate trends
        const trends = {
            improving: results.filter(r => r.comparison?.trend === 'improving').length,
            declining: results.filter(r => r.comparison?.trend === 'declining').length,
            stable: results.filter(r => r.comparison?.trend === 'stable').length,
        };

        return {
            totalSites: results.length,
            averageScore,
            passingCount,
            failingCount,
            warningCount,
            totalCritical,
            totalHigh,
            worstPerforming,
            bestPerforming,
            byStatus,
            trends: trends.improving + trends.declining + trends.stable > 0 ? trends : undefined,
        };
    }

    /**
     * Build HTML dashboard
     */
    private buildHtml(results: FleetSiteResult[], summary: FleetSummary): string {
        const generatedAt = new Date().toLocaleString();

        const trendHtml = summary.trends ? `
            <div class="card">
                <div class="card-value">${summary.trends.improving} <span style="font-size:1rem;">📈</span></div>
                <div class="card-label">Improving</div>
            </div>
            <div class="card">
                <div class="card-value">${summary.trends.declining} <span style="font-size:1rem;">📉</span></div>
                <div class="card-label">Declining</div>
            </div>
        ` : '';

        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Fleet Compliance Dashboard</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --border-color: #30363d;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        h1 { margin: 0; font-size: 2rem; }
        .meta-info { color: var(--text-secondary); font-size: 0.9rem; }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background: var(--bg-secondary);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        .card-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 10px 0;
        }
        .card-label {
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 1px;
        }
        .score-good { color: var(--accent-green); }
        .score-warning { color: var(--accent-yellow); }
        .score-critical { color: var(--accent-red); }

        .section-title {
            font-size: 1.25rem;
            margin: 30px 0 15px;
            color: var(--text-primary);
        }

        .fleet-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
        }
        .fleet-table th {
            text-align: left;
            padding: 14px 20px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }
        .fleet-table td {
            padding: 14px 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .fleet-table tr:last-child td { border-bottom: none; }
        .fleet-table tr:hover { background: var(--bg-tertiary); }

        .status-badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-pass { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .status-warning { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
        .status-fail { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }

        .score-cell { font-weight: 700; font-size: 1.1rem; }
        .report-link {
            color: var(--accent-blue);
            text-decoration: none;
            font-weight: 500;
            font-size: 0.85rem;
        }
        .report-link:hover { text-decoration: underline; }

        .trend-indicator {
            font-size: 0.8rem;
            margin-left: 5px;
        }

        .score-breakdown {
            display: flex;
            gap: 8px;
            margin-top: 4px;
        }
        .score-breakdown span {
            font-size: 0.7rem;
            padding: 2px 6px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            color: var(--text-secondary);
        }

        .alerts-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 30px;
        }
        .alert-card {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }
        .alert-card h3 {
            margin: 0 0 15px;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .alert-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .alert-list li {
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .alert-list li:last-child { border-bottom: none; }

        .export-btn {
            background: var(--accent-blue);
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .export-btn:hover { opacity: 0.9; }

        @media (max-width: 768px) {
            .summary-cards { grid-template-columns: repeat(2, 1fr); }
            .alerts-section { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1>🏢 Enterprise Fleet Compliance</h1>
                <div class="meta-info">Generated on ${generatedAt} • ${summary.totalSites} sites</div>
            </div>
            <div>
                <button class="export-btn" onclick="exportToCsv()">📥 Export CSV</button>
            </div>
        </header>

        <section class="summary-cards">
            <div class="card">
                <div class="card-value ${summary.averageScore >= 90 ? 'score-good' : summary.averageScore >= 70 ? 'score-warning' : 'score-critical'}">${summary.averageScore}</div>
                <div class="card-label">Average Fleet Score</div>
            </div>
            <div class="card">
                <div class="card-value score-good">${summary.passingCount}</div>
                <div class="card-label">Passing Sites</div>
            </div>
            <div class="card">
                <div class="card-value score-critical">${summary.failingCount}</div>
                <div class="card-label">Failing Sites</div>
            </div>
            <div class="card">
                <div class="card-value score-critical">${summary.totalCritical}</div>
                <div class="card-label">Critical Issues</div>
            </div>
            <div class="card">
                <div class="card-value score-warning">${summary.totalHigh}</div>
                <div class="card-label">High Issues</div>
            </div>
            ${trendHtml}
        </section>

        <section class="alerts-section">
            <div class="alert-card">
                <h3>🚨 Worst Performing</h3>
                <ul class="alert-list">
                    ${summary.worstPerforming.map(site => `
                    <li>
                        <span>${site.domain}</span>
                        <span class="score-cell score-critical">${site.healthScore}</span>
                    </li>
                    `).join('')}
                </ul>
            </div>
            <div class="alert-card">
                <h3>🏆 Best Performing</h3>
                <ul class="alert-list">
                    ${summary.bestPerforming.map(site => `
                    <li>
                        <span>${site.domain}</span>
                        <span class="score-cell score-good">${site.healthScore}</span>
                    </li>
                    `).join('')}
                </ul>
            </div>
        </section>

        <h2 class="section-title">All Sites</h2>
        <section>
            <table class="fleet-table">
                <thead>
                    <tr>
                        <th>Domain / Application</th>
                        <th>Health Score</th>
                        <th>Scores</th>
                        <th>Status</th>
                        <th>Issues</th>
                        <th>Trend</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(site => `
                    <tr>
                        <td>
                            <div style="font-weight:600; color:var(--text-primary);">${site.domain}</div>
                            <div style="font-size:0.75rem; color:var(--text-secondary);">${site.url}</div>
                        </td>
                        <td class="score-cell ${site.healthScore >= 90 ? 'score-good' : site.healthScore >= 70 ? 'score-warning' : 'score-critical'}">
                            ${site.healthScore}
                        </td>
                        <td>
                            <div class="score-breakdown">
                                ${site.scores?.performance !== undefined ? `<span>P:${site.scores.performance}</span>` : ''}
                                ${site.scores?.accessibility !== undefined ? `<span>A:${site.scores.accessibility}</span>` : ''}
                                ${site.scores?.security !== undefined ? `<span>S:${site.scores.security}</span>` : ''}
                            </div>
                        </td>
                        <td>
                            <span class="status-badge status-${site.status}">${site.status}</span>
                        </td>
                        <td>
                            <span style="${site.criticalIssues > 0 ? 'color:var(--accent-red); font-weight:700;' : ''}">${site.criticalIssues}C</span>
                            ${site.highIssues ? `<span style="color:var(--accent-yellow);"> / ${site.highIssues}H</span>` : ''}
                        </td>
                        <td>
                            ${site.comparison ? `
                            <span class="trend-indicator">
                                ${site.comparison.trend === 'improving' ? '📈' : site.comparison.trend === 'declining' ? '📉' : '➡️'}
                                ${site.comparison.previousScore ? `(was ${site.comparison.previousScore})` : ''}
                            </span>
                            ` : '<span style="color:var(--text-secondary);">—</span>'}
                        </td>
                        <td>
                            <a href="${site.reportPath}" class="report-link">View Report →</a>
                        </td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </section>
    </div>

    <script>
        function exportToCsv() {
            const data = ${JSON.stringify(results.map(r => ({
                domain: r.domain,
                url: r.url,
                healthScore: r.healthScore,
                status: r.status,
                criticalIssues: r.criticalIssues,
                highIssues: r.highIssues || 0,
                performance: r.scores?.performance || '',
                accessibility: r.scores?.accessibility || '',
                security: r.scores?.security || '',
            })))};
            
            const headers = Object.keys(data[0]).join(',');
            const rows = data.map(r => Object.values(r).join(',')).join('\\n');
            const csv = headers + '\\n' + rows;
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'fleet-compliance-' + new Date().toISOString().split('T')[0] + '.csv';
            a.click();
        }
    </script>
</body>
</html>
        `;
    }

    /**
     * Generate a markdown summary
     */
    generateMarkdownSummary(results: FleetSiteResult[]): string {
        const summary = this.calculateSummary(results);
        const lines: string[] = [
            '# 🏢 Fleet Compliance Summary',
            '',
            `**Generated:** ${new Date().toLocaleString()}`,
            '',
            '## Overview',
            '',
            `| Metric | Value |`,
            `|--------|-------|`,
            `| Total Sites | ${summary.totalSites} |`,
            `| Average Score | ${summary.averageScore}/100 |`,
            `| Passing | ${summary.passingCount} |`,
            `| Failing | ${summary.failingCount} |`,
            `| Critical Issues | ${summary.totalCritical} |`,
            '',
            '## Worst Performing',
            '',
        ];

        for (const site of summary.worstPerforming) {
            lines.push(`- **${site.domain}**: ${site.healthScore}/100 (${site.criticalIssues} critical)`);
        }

        lines.push('', '## All Sites', '', '| Domain | Score | Status | Critical |', '|--------|-------|--------|----------|');

        for (const site of results) {
            lines.push(`| ${site.domain} | ${site.healthScore} | ${site.status} | ${site.criticalIssues} |`);
        }

        return lines.join('\n');
    }
}
