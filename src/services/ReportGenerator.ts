/**
 * ReportGenerator Service
 * 
 * Generates a professional Markdown summary of the compliance audit.
 * Integrates data from authentication, crawler, lighthouse, and ZAP security scans.
 */

import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';
import { getConfig } from '../config/env';
import { PageCrawlResult } from './CrawlerService';
import { A11yViolation } from './A11yScanner';

/**
 * Interface representing the full report data structure
 */
export interface ReportData {
    meta: {
        version: string;
        generatedAt: string;
        targetUrl: string;
        duration: number;
    };
    authentication: {
        success: boolean;
        duration: number;
        message?: string;
    };
    crawl?: {
        pagesVisited: number;
        failedPages: number;
        suspiciousPages: number;
        pageResults: PageCrawlResult[];
    };
    integrity?: {
        testsRun: number;
        passed: number;
        failed: number;
        results: Array<{
            url: string;
            passed: boolean;
            checkType: string;
            details: string;
        }>;
    };
    network_incidents?: Array<{
        url: string;
        method: string;
        type: string;
        status: number;
        details?: string;
    }>;
    leaked_secrets?: Array<{
        type: string;
        fileUrl: string;
        maskedValue: string;
        risk: string;
    }>;
    lighthouse?: {
        performance: number;
        accessibility: number;
        bestPractices: number;
        seo: number;
        pwa: number;
    };
    security_alerts?: Array<{
        alert: string;
        risk: string;
        url: string;
        description: string;
        solution: string;
    }>;
    summary?: {
        performanceScore: number;
        accessibilityScore: number;
        seoScore: number;
        highRiskAlerts: number;
        mediumRiskAlerts: number;
        passedAudit: boolean;
    };
}

export class ReportGenerator {
    private config = getConfig();

    /**
     * Encodes a string to be safe for Markdown tables
     */
    private escapeMarkdown(text: string): string {
        return text ? text.replace(/\|/g, '\\|').replace(/\n/g, ' ') : '';
    }

    /**
     * Generates the markdown report
     */
    public async generate(data: ReportData): Promise<void> {
        logger.info('Generating Markdown report...');
        const reportPath = path.join(this.config.REPORTS_DIR, 'AUDIT_SUMMARY.md');

        let md = '# 🛡️ Live Site Compliance Report\n\n';
        md += `**Target:** [${data.meta.targetUrl}](${data.meta.targetUrl})  \n`;
        md += `**Date:** ${new Date(data.meta.generatedAt).toLocaleString()}  \n`;
        md += `**Duration:** ${(data.meta.duration / 1000).toFixed(2)}s  \n`;
        md += `**Status:** ${data.summary?.passedAudit ? '✅ **PASSED**' : '❌ **FAILED**'}  \n\n`;

        // 1. Executive Summary
        md += '## 📊 Executive Summary\n\n';
        md += '| Metric | Value | Status |\n';
        md += '| :--- | :--- | :--- |\n';

        // Auth Status
        const authStatus = data.authentication.success ? '✅ Success' : '❌ Failed';
        md += `| **Authentication** | ${data.authentication.duration}ms | ${authStatus} |\n`;

        // Crawler Stats
        if (data.crawl) {
            const crawlStatus = data.crawl.failedPages === 0 ? '✅ Healthy' : `⚠️ ${data.crawl.failedPages} Failures`;
            md += `| **Pages Scanned** | ${data.crawl.pagesVisited} | ${crawlStatus} |\n`;
        }

        // Integrity Stats
        if (data.integrity) {
            const integrityStatus = data.integrity.failed === 0 ? '✅ Verified' : `❌ ${data.integrity.failed} Failures`;
            md += `| **Data Integrity** | ${data.integrity.testsRun} Tests | ${integrityStatus} |\n`;
        }

        // Network Stats (New)
        if (data.network_incidents) {
            const netCount = data.network_incidents.length;
            const netStatus = netCount === 0 ? '✅ Optimized' : `⚠️ ${netCount} Issues`;
            md += `| **Network Health** | ${netCount} Incidents | ${netStatus} |\n`;
        }

        // Lighthouse
        if (data.lighthouse) {
            const perfScore = data.lighthouse.performance * 100;
            const perfIcon = perfScore >= 90 ? '🟢' : perfScore >= 50 ? 'kB' : '🔴';
            md += `| **Performance (Lighthouse)** | ${perfScore.toFixed(0)}/100 | ${perfIcon} |\n`;
        }

        // Security
        if (data.summary) {
            const securityIcon = data.summary.highRiskAlerts === 0 ? '🟢' : '🔴';
            md += `| **Security Alerts** | High: ${data.summary.highRiskAlerts}, Med: ${data.summary.mediumRiskAlerts} | ${securityIcon} |\n`;
        }

        md += '\n---\n\n';

        // 2. Data Integrity Section (New)
        if (data.integrity && data.integrity.testsRun > 0) {
            md += '## 🧬 Data Integrity & Logic Tests\n\n';
            md += '> Verifying complex data structures (loadouts, weapon stats) render correctly.\n\n';
            md += '| Status | Test Type | URL | Details |\n';
            md += '| :--- | :--- | :--- | :--- |\n';

            data.integrity.results.forEach(res => {
                const icon = res.passed ? '✅' : '❌';
                const type = res.checkType === 'loadout_completion' ? 'Loadout Build' : 'Text Match';
                md += `| ${icon} | ${type} | \`${res.url}\` | ${this.escapeMarkdown(res.details)} |\n`;
            });
            md += '\n';
        }

        // 3. Visual Regression Section (New)
        const visualFailures = data.crawl?.pageResults.filter(r => r.visualResult && !r.visualResult.passed) || [];
        if (visualFailures.length > 0) {
            md += '## 👁️ Visual Regression Failures\n\n';
            md += '> **Attention:** Visual layout changes detected exceeding 5% threshold.\n\n';

            visualFailures.forEach(r => {
                const res = r.visualResult!;
                md += `### ${this.escapeMarkdown(res.pageName)}\n`;
                md += `- **URL:** \`${r.url}\`\n`;
                md += `- **Difference:** ${(res.diffPercentage * 100).toFixed(2)}%\n`;
                if (res.diffImagePath) {
                    // Assuming relative path for markdown
                    const relativePath = `../snapshots/diff/${path.basename(res.diffImagePath)}`;
                    md += `![Diff](${relativePath})\n\n`;
                }
            });
            md += '---\n\n';
        }

        // 3.5. Network Incidents Section
        if (data.network_incidents && data.network_incidents.length > 0) {
            md += '## 🐌 Network Performance & Errors\n\n';
            md += '> Detected slow queries (>500ms), heavy payloads (>100KB), or HTTP errors.\n\n';
            md += '| Type | Method | Status | Details | URL |\n';
            md += '| :--- | :--- | :--- | :--- | :--- |\n';

            data.network_incidents.forEach(inc => {
                const icon = inc.type === 'http_error' ? '❌' : inc.type === 'slow_response' ? '⏳' : '🐘';
                const prettyType = inc.type.replace('_', ' ').toUpperCase();
                const details = inc.details ? `\`${inc.details}\`` : '-';
                md += `| ${icon} ${prettyType} | ${inc.method} | ${inc.status} | ${details} | \`${inc.url.substring(0, 50)}...\` |\n`;
            });
            md += '\n';
        }

        // 4. Performance Section
        if (data.lighthouse) {
            md += '## ⚡ Performance & Quality (Lighthouse)\n\n';
            md += '| Category | Score | Grade |\n';
            md += '| :--- | :--- | :--- |\n';

            const metrics = [
                { name: 'Performance', score: data.lighthouse.performance },
                { name: 'Accessibility', score: data.lighthouse.accessibility },
                { name: 'Best Practices', score: data.lighthouse.bestPractices },
                { name: 'SEO', score: data.lighthouse.seo },
            ];

            metrics.forEach(m => {
                const val = m.score * 100;
                const grade = val >= 90 ? '🟢 Excellent' : val >= 50 ? 'kB Average' : '🔴 Poor';
                md += `| ${m.name} | **${val.toFixed(0)}** | ${grade} |\n`;
            });
            md += '\n';
        }

        // 3. Security Section
        if ((data.security_alerts && data.security_alerts.length > 0) || (data.leaked_secrets && data.leaked_secrets.length > 0)) {
            md += '## 🔒 Security Vulnerabilities\n\n';

            // 3.1 Leaked Secrets (CRITICAL)
            if (data.leaked_secrets && data.leaked_secrets.length > 0) {
                md += '### 🚨 HARDCODED SECRETS DETECTED\n';
                md += '> **CRITICAL WARNING:** API keys or credentials were found in client-side JavaScript.\n\n';

                data.leaked_secrets.forEach(secret => {
                    md += `- **Type:** ${secret.type}\n`;
                    md += `  - **Risk:** ${secret.risk}\n`;
                    md += `  - **File:** \`${secret.fileUrl}\`\n`;
                    md += `  - **Masked Value:** \`${secret.maskedValue}\`\n\n`;
                });
                md += '---\n\n';
            }

            // 3.2 ZAP Alerts
            if (data.security_alerts && data.security_alerts.length > 0) {
                // Group by risk
                const high = data.security_alerts.filter(a => a.risk === 'High');
                const medium = data.security_alerts.filter(a => a.risk === 'Medium');
                const low = data.security_alerts.filter(a => a.risk === 'Low');

                if (high.length > 0) {
                    md += '### 🚨 High Risk\n';
                    high.forEach(alert => {
                        md += `- **${this.escapeMarkdown(alert.alert)}**\n`;
                        md += `  - *URL:* \`${alert.url}\`\n`;
                        md += `  - *Description:* ${this.escapeMarkdown(alert.description.substring(0, 200))}...\n\n`;
                    });
                }

                if (medium.length > 0) {
                    md += '### ⚠️ Medium Risk\n';
                    medium.forEach(alert => {
                        md += `- **${this.escapeMarkdown(alert.alert)}**\n`;
                        md += `  - *URL:* \`${alert.url}\`\n\n`;
                    });
                }

                if (low.length > 0) {
                    md += '### ℹ️ Low Risk\n';
                    md += `<details><summary>Click to view ${low.length} low risk alerts</summary>\n\n`;
                    low.forEach(alert => {
                        md += `- ${this.escapeMarkdown(alert.alert)} (${alert.url})\n`;
                    });
                    md += '\n</details>\n\n';
                }
            } else {
                md += '## 🔒 Security\n\nNo high or medium risk vulnerabilities detected. ✅\n\n';
            }
        }

        // 3.5 Broken Assets (New)
        const assetFailures = data.crawl?.pageResults.filter(r => r.assetResult && r.assetResult.brokenImages.length > 0) || [];
        if (assetFailures.length > 0) {
            md += '## 🖼️ Broken Assets\n\n';
            md += '> **Warning:** Images failed to load or have 0 dimensions.\n\n';

            assetFailures.forEach(r => {
                md += `### ${this.escapeMarkdown(r.visualResult?.pageName || r.url)}\n`;
                md += `- **URL:** \`${r.url}\`\n`;
                r.assetResult!.brokenImages.forEach(img => {
                    md += `- ❌ \`${img}\`\n`;
                });
                md += '\n';
            });
            md += '---\n\n';
        }

        // 3.6 Broken Links (New)
        const linkFailures = data.crawl?.pageResults.filter(r => r.linkCheckResult && r.linkCheckResult.brokenLinks.length > 0) || [];
        if (linkFailures.length > 0) {
            md += '## 🔗 Broken Links\n\n';
            md += '> **Warning:** Internal links that returned 404 or 500 status.\n\n';

            linkFailures.forEach(r => {
                md += `### ${this.escapeMarkdown(r.visualResult?.pageName || r.url)}\n`;
                md += `- **Page:** \`${r.url}\`\n`;
                r.linkCheckResult!.brokenLinks.forEach(link => {
                    md += `- ❌ \`${link.url}\` (${link.status})\n`;
                });
                md += '\n';
            });
            md += '---\n\n';
        }

        // 3.7 SEO Defects
        const seoFailures = data.crawl?.pageResults.filter(r => r.seoResult && (!r.seoResult.valid || r.seoResult.warnings.length > 0)) || [];
        if (seoFailures.length > 0) {
            md += '## 🔍 SEO Defects\n\n';
            md += '> **Warning:** Pages missing social meta tags or having invalid og:images.\n\n';

            seoFailures.forEach(r => {
                md += `### ${this.escapeMarkdown(r.visualResult?.pageName || r.url)}\n`;
                md += `- **Page:** \`${r.url}\`\n`;

                if (r.seoResult!.missingTags.length > 0) {
                    md += `- ❌ **Missing Tags:** ${r.seoResult!.missingTags.map((t: string) => '`' + t + '`').join(', ')}\n`;
                }

                r.seoResult!.warnings.forEach((w: string) => {
                    md += `- ⚠️ ${w}\n`;
                });

                md += '\n';
            });
            md += '---\n\n';
        }

        // 3.8 Functional Testing (New)
        const interactionFailures = data.crawl?.pageResults.filter(r => r.interactionResult && !r.interactionResult.passed) || [];
        const interactionPasses = data.crawl?.pageResults.filter(r => r.interactionResult && r.interactionResult.passed) || [];

        if (interactionFailures.length > 0 || interactionPasses.length > 0) {
            md += '## 🧪 Functional Testing\n\n';

            if (interactionFailures.length > 0) {
                interactionFailures.forEach(r => {
                    const res = r.interactionResult!;
                    md += `### ❌ ${res.feature}: FAIL\n`;
                    md += `> Error on ${r.visualResult?.pageName || r.url}\n\n`;
                    md += `* **Error:** ${res.error}\n`;
                    md += `* **Duration:** ${res.duration}ms\n\n`;
                });
            }

            if (interactionPasses.length > 0) {
                interactionPasses.forEach(r => {
                    const res = r.interactionResult!;
                    md += `### ✅ ${res.feature}: PASS\n`;
                    md += `> Verified on ${r.visualResult?.pageName || r.url}\n\n`;
                    md += `* **Duration:** ${res.duration}ms\n\n`;
                });
            }
            md += '---\n\n';
        }

        // 3.9 Resilience Testing
        const resilienceResults = data.crawl?.pageResults.filter(r => r.resilienceResult).map(r => ({ ...r.resilienceResult!, page: r.url })) || [];
        if (resilienceResults.length > 0) {
            md += '## 🐌 Network Resilience (3G)\n\n';
            resilienceResults.forEach(res => {
                const icon = res.passed ? '✅' : '❌';
                md += `### ${icon} ${res.feature}\n`;
                md += `> Tested on ${res.page}\n\n`;
                md += `* **Load Time:** ${res.loadTime}ms\n`;
                md += `* **Loading State:** ${res.skeletonDetected ? '✅ Skeleton Detected' : '⚠️ No Skeleton Detected'}\n`;
                if (res.error) md += `* **Error:** ${res.error}\n`;
                md += '\n';
            });
            md += '---\n\n';
        }

        // 3.10 Accessibility Compliance
        const a11yResults = data.crawl?.pageResults.filter(r => r.a11yResult).map(r => ({ ...r.a11yResult!, page: r.url })) || [];
        if (a11yResults.length > 0) {
            md += '## ♿ Accessibility Compliance\n\n';
            a11yResults.forEach(res => {
                const icon = res.passed ? '✅' : '❌';
                md += `### ${icon} Scan on ${res.page}\n`;
                md += `**Score:** ${res.score}/100\n\n`;

                if (res.violations.length > 0) {
                    md += '| Impact | Description | Help |\n';
                    md += '| :--- | :--- | :--- |\n';
                    res.violations.forEach((v: A11yViolation) => {
                        const impactIcon = v.impact === 'critical' ? '🔴' : v.impact === 'serious' ? '🟠' : '🟡';
                        md += `| ${impactIcon} ${v.impact} | ${v.description} (${v.nodes} nodes) | [Link](${v.helpUrl}) |\n`;
                    });
                    md += '\n';
                } else {
                    md += '*No violations found.*\n\n';
                }
            });
            md += '---\n\n';
        }

        // 4. Crawler Log
        if (data.crawl && data.crawl.pageResults) {
            md += '## 🕸️ Crawler Log\n\n';
            md += '| HTTP Status | URL | Title | Error |\n';
            md += '| :--- | :--- | :--- | :--- |\n';

            data.crawl.pageResults.forEach(page => {
                const statusIcon = page.status === 200 ? '✅' : page.status === 404 ? '❌' : '⚠️';
                const error = page.error ? `\`${page.error.substring(0, 30)}\`...` : '-';
                md += `| ${statusIcon} ${page.status || 'N/A'} | \`${page.url}\` | ${this.escapeMarkdown(page.title)} | ${error} |\n`;
            });
            md += '\n';
        }

        // 5. Failures & Screenshots
        md += '## 📸 Failure Evidence\n\n';

        try {
            const screenshotsDir = path.resolve(this.config.SCREENSHOTS_DIR);
            if (fs.existsSync(screenshotsDir)) {
                const files = fs.readdirSync(screenshotsDir);
                // Filter for images and sort by newest
                const images = files
                    .filter(f => f.endsWith('.png') || f.endsWith('.jpg'))
                    .sort((a, b) => {
                        return fs.statSync(path.join(screenshotsDir, b)).mtime.getTime() -
                            fs.statSync(path.join(screenshotsDir, a)).mtime.getTime();
                    });

                if (images.length > 0) {
                    md += 'Recent screenshots captured during execution:\n\n';
                    images.slice(0, 5).forEach(img => {
                        const imgPath = path.join(screenshotsDir, img);
                        // Use relative path for markdown if report is in root or strict logical link
                        // Trying relative from reports dir to screenshots dir
                        const relativePath = `../screenshots/${img}`;

                        md += `### ${img}\n`;
                        md += `![${img}](${relativePath})\n\n`;
                    });
                } else {
                    md += '*No screenshots captured.*\n';
                }
            }
        } catch (error) {
            logger.warn(`Could not list screenshots: ${error}`);
            md += '*Error listing screenshots.*\n';
        }

        // Write file
        fs.writeFileSync(reportPath, md);
        logger.info(`Markdown report generated: ${reportPath}`);
    }
}
