import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

export interface FleetSiteResult {
    url: string;
    domain: string;
    healthScore: number;
    reportPath: string;
    criticalIssues: number;
    status: 'pass' | 'fail' | 'warning';
}

export class FleetReportGenerator {
    private reportsDir: string;

    constructor(reportsDir: string = './reports') {
        this.reportsDir = reportsDir;
    }

    async generate(results: FleetSiteResult[]): Promise<string> {
        logger.info(`Generating Fleet Dashboard for ${results.length} sites...`);

        const html = this.buildHtml(results);
        const outputPath = path.join(this.reportsDir, 'fleet-dashboard.html');

        // Ensure directory exists
        if (!fs.existsSync(this.reportsDir)) {
            fs.mkdirSync(this.reportsDir, { recursive: true });
        }

        fs.writeFileSync(outputPath, html, 'utf-8');
        logger.info(`Fleet Dashboard generated at: ${outputPath}`);

        return outputPath;
    }

    private buildHtml(results: FleetSiteResult[]): string {
        const generatedAt = new Date().toLocaleString();
        const averageScore = Math.round(results.reduce((acc, r) => acc + r.healthScore, 0) / results.length) || 0;

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
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
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
            grid-template-columns: repeat(3, 1fr);
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
            font-size: 0.8rem;
            letter-spacing: 1px;
        }
        .score-good { color: var(--accent-green); }
        .score-warning { color: var(--accent-yellow); }
        .score-critical { color: var(--accent-red); }

        .fleet-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
        }
        .fleet-table th {
            text-align: left;
            padding: 16px 24px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
        }
        .fleet-table td {
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        .fleet-table tr:last-child td { border-bottom: none; }
        .fleet-table tr:hover { background: var(--bg-tertiary); }

        .status-badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
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
        }
        .report-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1>Enterprise Fleet Compliance</h1>
                <div class="meta-info">Generated on ${generatedAt}</div>
            </div>
            <div>
                <span class="status-badge status-pass">v1.2.0</span>
            </div>
        </header>

        <section class="summary-cards">
            <div class="card">
                <div class="card-value ${averageScore >= 90 ? 'score-good' : averageScore >= 70 ? 'score-warning' : 'score-critical'}">${averageScore}</div>
                <div class="card-label">Average Fleet Score</div>
            </div>
            <div class="card">
                <div class="card-value">${results.length}</div>
                <div class="card-label">Sites Scanned</div>
            </div>
            <div class="card">
                <div class="card-value score-critical">${results.reduce((acc, r) => acc + r.criticalIssues, 0)}</div>
                <div class="card-label">Total Critical Issues</div>
            </div>
        </section>

        <section>
            <table class="fleet-table">
                <thead>
                    <tr>
                        <th>Domain / Application</th>
                        <th>Health Score</th>
                        <th>Status</th>
                        <th>Critical Issues</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(site => `
                    <tr>
                        <td>
                            <div style="font-weight:600; color:var(--text-primary);">${site.domain}</div>
                            <div style="font-size:0.8rem; color:var(--text-secondary);">${site.url}</div>
                        </td>
                        <td class="score-cell ${site.healthScore >= 90 ? 'score-good' : site.healthScore >= 70 ? 'score-warning' : 'score-critical'}">
                            ${site.healthScore}
                        </td>
                        <td>
                            <span class="status-badge status-${site.status}">${site.status}</span>
                        </td>
                        <td>
                            <span style="${site.criticalIssues > 0 ? 'color:var(--accent-red); font-weight:700;' : ''}">
                                ${site.criticalIssues}
                            </span>
                        </td>
                        <td>
                            <a href="${site.reportPath}" class="report-link">View Audit Report →</a>
                        </td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </section>
    </div>
</body>
</html>
        `;
    }
}
