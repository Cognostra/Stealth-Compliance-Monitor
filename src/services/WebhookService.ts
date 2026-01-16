import { createConfig } from '../config/compliance.config';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';

/**
 * Webhook payload structure
 */
export interface WebhookPayload {
    event: string;
    target: string;
    timestamp: string;
    health_score: number | string;
    critical_issues: number;
    high_issues: number;
    total_issues: number;
    status: 'PASS' | 'FAIL' | 'WARNING';
    report_link: string;
    details: {
        performance?: number;
        accessibility?: number;
        seo?: number;
        security?: number;
        vulnerabilities?: number;
        secretsLeaked?: number;
        a11yViolations?: number;
    };
    comparison?: {
        previousScore: number;
        scoreDiff: number;
        trend: 'improving' | 'declining' | 'stable';
        newIssues: number;
        resolvedIssues: number;
    };
}

/**
 * Slack message format
 */
interface SlackMessage {
    text?: string;
    attachments?: SlackAttachment[];
    blocks?: SlackBlock[];
}

interface SlackAttachment {
    color: string;
    title: string;
    text?: string;
    fields?: Array<{ title: string; value: string; short?: boolean }>;
    footer?: string;
    ts?: number;
}

interface SlackBlock {
    type: string;
    text?: { type: string; text: string; emoji?: boolean };
    elements?: unknown[];
    accessory?: unknown;
}

/**
 * Microsoft Teams message format
 */
interface TeamsMessage {
    '@type': string;
    '@context': string;
    themeColor: string;
    summary: string;
    sections: Array<{
        activityTitle?: string;
        activitySubtitle?: string;
        activityImage?: string;
        facts?: Array<{ name: string; value: string }>;
        markdown?: boolean;
        text?: string;
    }>;
    potentialAction?: Array<{
        '@type': string;
        name: string;
        targets?: Array<{ os: string; uri: string }>;
    }>;
}

/**
 * Discord message format
 */
interface DiscordMessage {
    content?: string;
    embeds?: Array<{
        title: string;
        description?: string;
        color: number;
        fields?: Array<{ name: string; value: string; inline?: boolean }>;
        footer?: { text: string };
        timestamp?: string;
    }>;
}

/**
 * Result of webhook delivery
 */
export interface WebhookResult {
    success: boolean;
    statusCode?: number;
    error?: string;
    retryable?: boolean;
}

/**
 * Universal Webhook Service
 * Sends compliance alerts to external platforms (Slack, Teams, Discord, Zapier, etc.)
 * Automatically detects webhook type and formats messages appropriately.
 */
export class WebhookService {
    private static readonly MAX_RETRIES = 3;
    private static readonly RETRY_DELAY_MS = 1000;

    /**
     * Send an alert to the configured webhook
     * @param scanSummary - Summary object from the scan report
     * @param targetUrl - The URL that was scanned
     * @param reportPath - Path to the generated report
     * @param comparison - Optional comparison with previous scan
     */
    static async sendAlert(
        scanSummary: any, 
        targetUrl: string, 
        reportPath: string,
        comparison?: WebhookPayload['comparison']
    ): Promise<WebhookResult> {
        const config = createConfig();

        // Safe Check
        if (!config.webhook || !config.webhook.url) {
            logger.debug('Webhook integration disabled (no URL configured)');
            return { success: true };
        }

        const criticalCount = scanSummary.securityCritical || 0;
        const highCount = scanSummary.securityHigh || 0;
        const totalIssues = criticalCount + highCount +
            (scanSummary.highRiskAlerts || 0) +
            (scanSummary.mediumRiskAlerts || 0);

        // Filter Logic
        if (config.webhook.events === 'critical') {
            if (criticalCount === 0 && highCount === 0) {
                logger.debug('Webhook skipped: No critical/high issues found and filter is set to "critical"');
                return { success: true };
            }
        }

        logger.info(`Sending compliance alert to webhook: ${config.webhook.url}`);

        // Determine status
        let status: 'PASS' | 'FAIL' | 'WARNING';
        if (criticalCount > 0) {
            status = 'FAIL';
        } else if (highCount > 0) {
            status = 'WARNING';
        } else {
            status = 'PASS';
        }

        // Build payload
        const payload: WebhookPayload = {
            event: 'scan_completed',
            target: targetUrl,
            timestamp: new Date().toISOString(),
            health_score: scanSummary.healthScore || 'N/A',
            critical_issues: criticalCount,
            high_issues: highCount,
            total_issues: totalIssues,
            status,
            report_link: reportPath,
            details: {
                performance: scanSummary.performanceScore,
                accessibility: scanSummary.accessibilityScore,
                seo: scanSummary.seoScore,
                security: scanSummary.securityScore,
                vulnerabilities: scanSummary.vulnerableLibraries,
                secretsLeaked: scanSummary.leakedSecrets,
                a11yViolations: scanSummary.a11yViolations,
            },
        };

        if (comparison) {
            payload.comparison = comparison;
        }

        // Detect webhook type and format message
        const webhookUrl = config.webhook.url;
        let formattedPayload: unknown;
        let contentType = 'application/json';

        if (WebhookService.isSlackWebhook(webhookUrl)) {
            formattedPayload = WebhookService.formatForSlack(payload);
        } else if (WebhookService.isTeamsWebhook(webhookUrl)) {
            formattedPayload = WebhookService.formatForTeams(payload);
        } else if (WebhookService.isDiscordWebhook(webhookUrl)) {
            formattedPayload = WebhookService.formatForDiscord(payload);
        } else {
            // Generic JSON payload
            formattedPayload = payload;
        }

        // Build headers
        const headers: Record<string, string> = {
            'Content-Type': contentType,
            'User-Agent': config.USER_AGENT,
        };

        // Add HMAC signature if secret is provided
        if (config.webhook.secret) {
            const bodyString = JSON.stringify(formattedPayload);
            const hmac = crypto.createHmac('sha256', config.webhook.secret);
            const signature = hmac.update(bodyString).digest('hex');
            headers['X-Compliance-Signature'] = `sha256=${signature}`;
            headers['X-Hub-Signature-256'] = `sha256=${signature}`; // GitHub style
        }

        // Send with retries
        return await WebhookService.sendWithRetry(webhookUrl, formattedPayload, headers);
    }

    /**
     * Send webhook with retry logic
     */
    private static async sendWithRetry(
        url: string, 
        payload: unknown, 
        headers: Record<string, string>
    ): Promise<WebhookResult> {
        let lastError: string = '';

        for (let attempt = 1; attempt <= WebhookService.MAX_RETRIES; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 15000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(payload),
                    signal: controller.signal,
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    logger.info(`Webhook alert sent successfully (attempt ${attempt})`);
                    return { success: true, statusCode: response.status };
                }

                // Check if retryable
                const retryable = response.status >= 500 || response.status === 429;
                lastError = `${response.status} ${response.statusText}`;

                if (!retryable || attempt === WebhookService.MAX_RETRIES) {
                    logger.warn(`Webhook failed: ${lastError}`);
                    return { 
                        success: false, 
                        statusCode: response.status, 
                        error: lastError,
                        retryable 
                    };
                }

                // Wait before retry (exponential backoff)
                const delay = WebhookService.RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                logger.debug(`Webhook attempt ${attempt} failed, retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));

            } catch (error) {
                lastError = error instanceof Error ? error.message : String(error);
                
                if (attempt === WebhookService.MAX_RETRIES) {
                    logger.warn(`Webhook execution error: ${lastError}`);
                    return { success: false, error: lastError, retryable: true };
                }

                // Wait before retry
                const delay = WebhookService.RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        return { success: false, error: lastError, retryable: true };
    }

    /**
     * Check if URL is a Slack webhook
     */
    private static isSlackWebhook(url: string): boolean {
        return url.includes('hooks.slack.com') || url.includes('slack.com/api');
    }

    /**
     * Check if URL is a Microsoft Teams webhook
     */
    private static isTeamsWebhook(url: string): boolean {
        return url.includes('webhook.office.com') || url.includes('outlook.office.com');
    }

    /**
     * Check if URL is a Discord webhook
     */
    private static isDiscordWebhook(url: string): boolean {
        return url.includes('discord.com/api/webhooks') || url.includes('discordapp.com/api/webhooks');
    }

    /**
     * Format payload for Slack
     */
    private static formatForSlack(payload: WebhookPayload): SlackMessage {
        const statusEmoji = payload.status === 'PASS' ? '✅' : payload.status === 'FAIL' ? '🚨' : '⚠️';
        const statusColor = payload.status === 'PASS' ? 'good' : payload.status === 'FAIL' ? 'danger' : 'warning';

        const fields: SlackAttachment['fields'] = [
            { title: 'Health Score', value: String(payload.health_score), short: true },
            { title: 'Status', value: payload.status, short: true },
            { title: 'Critical Issues', value: String(payload.critical_issues), short: true },
            { title: 'High Issues', value: String(payload.high_issues), short: true },
        ];

        if (payload.details.performance !== undefined) {
            fields.push({ title: 'Performance', value: `${payload.details.performance}/100`, short: true });
        }
        if (payload.details.accessibility !== undefined) {
            fields.push({ title: 'Accessibility', value: `${payload.details.accessibility}/100`, short: true });
        }

        if (payload.comparison) {
            const trendEmoji = payload.comparison.trend === 'improving' ? '📈' : 
                              payload.comparison.trend === 'declining' ? '📉' : '➡️';
            fields.push({ 
                title: 'Trend', 
                value: `${trendEmoji} ${payload.comparison.scoreDiff >= 0 ? '+' : ''}${payload.comparison.scoreDiff} points`, 
                short: true 
            });
        }

        return {
            text: `${statusEmoji} Compliance Scan Completed`,
            attachments: [{
                color: statusColor,
                title: `Scan Results for ${payload.target}`,
                fields,
                footer: 'Stealth Compliance Monitor',
                ts: Math.floor(Date.now() / 1000),
            }],
        };
    }

    /**
     * Format payload for Microsoft Teams
     */
    private static formatForTeams(payload: WebhookPayload): TeamsMessage {
        const themeColor = payload.status === 'PASS' ? '00FF00' : payload.status === 'FAIL' ? 'FF0000' : 'FFA500';
        const statusEmoji = payload.status === 'PASS' ? '✅' : payload.status === 'FAIL' ? '🚨' : '⚠️';

        const facts = [
            { name: 'Health Score', value: String(payload.health_score) },
            { name: 'Status', value: `${statusEmoji} ${payload.status}` },
            { name: 'Critical Issues', value: String(payload.critical_issues) },
            { name: 'High Issues', value: String(payload.high_issues) },
            { name: 'Total Issues', value: String(payload.total_issues) },
        ];

        if (payload.comparison) {
            facts.push({
                name: 'Trend',
                value: `${payload.comparison.trend.toUpperCase()} (${payload.comparison.scoreDiff >= 0 ? '+' : ''}${payload.comparison.scoreDiff} points)`,
            });
        }

        return {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            themeColor,
            summary: `Compliance Scan: ${payload.status}`,
            sections: [{
                activityTitle: `Compliance Scan Completed`,
                activitySubtitle: payload.target,
                facts,
                markdown: true,
            }],
            potentialAction: [{
                '@type': 'OpenUri',
                name: 'View Report',
                targets: [{ os: 'default', uri: payload.report_link }],
            }],
        };
    }

    /**
     * Format payload for Discord
     */
    private static formatForDiscord(payload: WebhookPayload): DiscordMessage {
        const color = payload.status === 'PASS' ? 0x00FF00 : payload.status === 'FAIL' ? 0xFF0000 : 0xFFA500;
        const statusEmoji = payload.status === 'PASS' ? '✅' : payload.status === 'FAIL' ? '🚨' : '⚠️';

        const fields = [
            { name: '🎯 Health Score', value: String(payload.health_score), inline: true },
            { name: '📊 Status', value: `${statusEmoji} ${payload.status}`, inline: true },
            { name: '🚨 Critical', value: String(payload.critical_issues), inline: true },
            { name: '⚠️ High', value: String(payload.high_issues), inline: true },
        ];

        if (payload.details.performance !== undefined) {
            fields.push({ name: '⚡ Performance', value: `${payload.details.performance}/100`, inline: true });
        }
        if (payload.details.accessibility !== undefined) {
            fields.push({ name: '♿ Accessibility', value: `${payload.details.accessibility}/100`, inline: true });
        }

        if (payload.comparison) {
            const trendEmoji = payload.comparison.trend === 'improving' ? '📈' : 
                              payload.comparison.trend === 'declining' ? '📉' : '➡️';
            fields.push({ 
                name: `${trendEmoji} Trend`, 
                value: `${payload.comparison.scoreDiff >= 0 ? '+' : ''}${payload.comparison.scoreDiff} points`, 
                inline: true 
            });
        }

        return {
            embeds: [{
                title: `Compliance Scan: ${payload.target}`,
                description: `Scan completed at ${new Date(payload.timestamp).toLocaleString()}`,
                color,
                fields,
                footer: { text: 'Stealth Compliance Monitor' },
                timestamp: payload.timestamp,
            }],
        };
    }

    /**
     * Send a custom event
     */
    static async sendCustomEvent(
        eventType: string,
        data: Record<string, unknown>,
        targetUrl?: string
    ): Promise<WebhookResult> {
        const config = createConfig();

        if (!config.webhook || !config.webhook.url) {
            return { success: true };
        }

        const payload = {
            event: eventType,
            timestamp: new Date().toISOString(),
            target: targetUrl || config.targetUrl,
            data,
        };

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'User-Agent': config.USER_AGENT,
        };

        if (config.webhook.secret) {
            const hmac = crypto.createHmac('sha256', config.webhook.secret);
            const signature = hmac.update(JSON.stringify(payload)).digest('hex');
            headers['X-Compliance-Signature'] = `sha256=${signature}`;
        }

        return await WebhookService.sendWithRetry(config.webhook.url, payload, headers);
    }

    /**
     * Test webhook connectivity
     */
    static async testConnection(): Promise<WebhookResult> {
        const config = createConfig();

        if (!config.webhook || !config.webhook.url) {
            return { success: false, error: 'No webhook URL configured' };
        }

        logger.info('Testing webhook connection...');

        return await WebhookService.sendCustomEvent('test', {
            message: 'This is a test message from Stealth Compliance Monitor',
            timestamp: new Date().toISOString(),
        });
    }
}
