import { createConfig } from '../config/compliance.config';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';

/**
 * Universal Webhook Service
 * Sends compliance alerts to external platforms (Slack, Teams, Discord, Zapier, etc.)
 */
export class WebhookService {

    /**
     * Send an alert to the configured webhook
     * @param scanSummary - Summary object from the scan report
     * @param targetUrl - The URL that was scanned
     * @param reportPath - Path to the generated report
     */
    static async sendAlert(scanSummary: any, targetUrl: string, reportPath: string): Promise<void> {
        const config = createConfig();

        // 1. Safe Check
        if (!config.webhook || !config.webhook.url) {
            logger.debug('Webhook integration disabled (no URL configured)');
            return;
        }

        const criticalCount = scanSummary.securityCritical || 0;
        const highCount = scanSummary.securityHigh || 0;
        const totalIssues = criticalCount + highCount +
            (scanSummary.highRiskAlerts || 0) +
            (scanSummary.mediumRiskAlerts || 0);

        // 2. Filter Logic
        if (config.webhook.events === 'critical') {
            if (criticalCount === 0 && highCount === 0) {
                logger.debug('Webhook skipped: No critical/high issues found and filter is set to "critical"');
                return;
            }
        }

        logger.info(`Sending compliance alert to webhook: ${config.webhook.url}`);

        // 3. Payload Construction
        // Calculate health score (approximate if not provided directly in summary)
        // We'll trust the summary passed contains relevant info.
        // Assuming scanSummary mirrors report.summary

        const payload = {
            event: 'scan_completed',
            target: targetUrl,
            timestamp: new Date().toISOString(),
            health_score: scanSummary.healthScore || 'N/A', // Caller might need to inject this if not in summary
            critical_issues: criticalCount,
            high_issues: highCount,
            total_issues: totalIssues,
            status: (criticalCount > 0) ? 'FAIL' : 'PASS',
            report_link: reportPath, // In a real scenario, this would be a URL, here it's a file path
            details: {
                performance: scanSummary.performanceScore,
                accessibility: scanSummary.accessibilityScore,
                seo: scanSummary.seoScore,
                vulnerabilities: scanSummary.vulnerableLibraries
            }
        };

        // Add HMAC signature if secret is provided
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'User-Agent': config.USER_AGENT
        };

        if (config.webhook.secret) {
            const hmac = crypto.createHmac('sha256', config.webhook.secret);
            const signature = hmac.update(JSON.stringify(payload)).digest('hex');
            headers['X-Compliance-Signature'] = signature;
        }

        // 4. Execution
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

            const response = await fetch(config.webhook.url, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                logger.info('Webhook alert sent successfully');
            } else {
                logger.warn(`Webhook failed with status: ${response.status} ${response.statusText}`);
            }
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.warn(`Webhook execution error: ${errMsg}`);
            // Graceful failure - do not crash the app
        }
    }
}
