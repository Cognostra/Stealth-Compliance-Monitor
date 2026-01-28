
import * as fs from 'node:fs';
import * as path from 'node:path';
import { chromium } from 'playwright';
import { logger } from '../utils/logger.js';
import { TrendDataPoint } from '../v3/services/TrendService.js';

export interface ReportData {
    meta: {
        version: string;
        generatedAt: string;
        targetUrl: string;
        scanType: string;
        duration: number;
        profile?: string;
    };
    lighthouse?: {
        scores: {
            performance: number;
            accessibility: number;
            bestPractices: number;
            seo: number;
        };
    };
    security_alerts?: Array<{ risk: string }>;
    security_assessment?: { findings: Array<{ severity: string }> };
}

export class ExecutiveReportGenerator {
    private reportsDir: string;

    constructor(reportsDir: string = './reports') {
        this.reportsDir = reportsDir;
    }

    /**
     * Generate PDF Executive Summary
     */
    public async generateReport(data: ReportData, healthScore: number, history: TrendDataPoint[]): Promise<string> {
        logger.info('Generating Executive Summary PDF...');
        
        // Ensure reports directory exists
        if (!fs.existsSync(this.reportsDir)) {
            fs.mkdirSync(this.reportsDir, { recursive: true });
        }

        const htmlContent = this.buildHtml(data, healthScore, history);
        const timestamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
        const filename = `executive-summary-${timestamp}.pdf`;
        const outputPath = path.join(this.reportsDir, filename);

        // Generate PDF using Playwright
        const browser = await chromium.launch();
        try {
            const page = await browser.newPage();
            await page.setContent(htmlContent);
            await page.pdf({
                path: outputPath,
                format: 'A4',
                printBackground: true,
                margin: {
                    top: '20px',
                    bottom: '40px',
                    left: '20px',
                    right: '20px'
                }
            });
            logger.info(`Executive Summary PDF generated: ${outputPath}`);
            return outputPath;
        } catch (error) {
            logger.error(`Failed to generate PDF: ${error}`);
            throw error;
        } finally {
            await browser.close();
        }
    }

    private buildHtml(data: ReportData, healthScore: number, _history: TrendDataPoint[]): string {
        const generationDate = new Date().toLocaleString();
        const scoreClass = this.getScoreClass(healthScore);
        
        const metrics = data.lighthouse?.scores || { performance: 0, accessibility: 0, bestPractices: 0, seo: 0 };
        const securityCount = (data.security_alerts?.length || 0) + (data.security_assessment?.findings?.length || 0);

        return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: 'Inter', sans-serif; color: #1e293b; padding: 40px; margin: 0; }
                h1, h2, h3 { color: #0f172a; margin-bottom: 0.5em; }
                .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: center; }
                .meta { color: #64748b; font-size: 0.9em; }
                .score-section { text-align: center; margin-bottom: 40px; padding: 30px; background: #f8fafc; border-radius: 12px; }
                .score-large { font-size: 4em; font-weight: 800; color: #3b82f6; }
                .score-good { color: #22c55e; }
                .score-warning { color: #f59e0b; }
                .score-critical { color: #ef4444; }
                .metrics-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 40px; }
                .metric-card { padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px; }
                .metric-label { color: #64748b; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.05em; }
                .metric-value { font-size: 1.5em; font-weight: 600; margin-top: 5px; }
                .footer { margin-top: 60px; text-align: center; color: #94a3b8; font-size: 0.8em; border-top: 1px solid #e2e8f0; padding-top: 20px; }
            </style>
        </head>
        <body>
            <header class="header">
                <div>
                    <h1>Executive Compliance Summary</h1>
                    <div class="meta">Target: ${data.meta.targetUrl}</div>
                </div>
                <div class="meta">${generationDate}</div>
            </header>

            <section class="score-section">
                <h3>Overall Health Score</h3>
                <div class="score-large ${scoreClass}">${healthScore} / 100</div>
            </section>

            <section class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">Performance</div>
                    <div class="metric-value">${metrics.performance}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Accessibility</div>
                    <div class="metric-value">${metrics.accessibility}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Security Findings</div>
                    <div class="metric-value">${securityCount}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">SEO Score</div>
                    <div class="metric-value">${metrics.seo}</div>
                </div>
            </section>

            <section>
                <h2>Assessment Summary</h2>
                <p>
                    This report provides a high-level overview of the compliance and performance status of <strong>${data.meta.targetUrl}</strong>.
                    The overall health score of <strong>${healthScore}</strong> indicates that the application is in 
                    <strong>${this.getHealthLabel(healthScore)}</strong> condition.
                </p>
            </section>

            <footer class="footer">
                Stealth Compliance Monitor v3.0 &bull; Automated Executive Report
            </footer>
        </body>
        </html>
        `;
    }

    private getScoreClass(score: number): string {
        if (score >= 90) return 'score-good';
        if (score >= 70) return 'score-warning';
        return 'score-critical';
    }

    private getHealthLabel(score: number): string {
        if (score >= 90) return 'Excellent';
        if (score >= 70) return 'Fair';
        return 'Critical';
    }
}
