/**
 * Messaging Integration Service
 *
 * Integrates with Slack and Microsoft Teams for real-time notifications
 * about audit results and compliance alerts.
 *
 * Features:
 * - Slack webhook and API integration
 * - Teams webhook integration
 * - Rich message formatting with blocks/cards
 * - Channel notifications for different severity levels
 * - Thread-based finding discussions
 */

import { logger } from '../../utils/logger.js';
import { fetchJson, fetchWithRetry } from '../../utils/api-client.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface MessagingConfig {
    slack?: {
        webhookUrl?: string;
        botToken?: string;
        channel?: string;
    };
    teams?: {
        webhookUrl?: string;
    };
}

export interface SlackBlock {
    type: string;
    text?: { type: string; text: string };
    fields?: Array<{ type: string; text: string }>;
    accessory?: unknown;
    elements?: unknown[];
}

export interface SlackMessage {
    text: string;
    blocks?: SlackBlock[];
    threadTs?: string;
    channel?: string;
    username?: string;
    iconEmoji?: string;
}

export interface TeamsCard {
    '@type': string;
    '@context': string;
    themeColor: string;
    summary: string;
    sections: Array<{
        activityTitle?: string;
        activitySubtitle?: string;
        facts?: Array<{ name: string; value: string }>;
        text?: string;
    }>;
    potentialAction?: Array<{
        '@type': string;
        name: string;
        targets?: Array<{ os: string; uri: string }>;
    }>;
}

export interface FindingForNotification {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    message: string;
    url?: string;
    file?: string;
    line?: number;
}

export interface NotificationResult {
    success: boolean;
    messageId?: string;
    threadTs?: string;
    error?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class MessagingIntegrationService {
    private config: MessagingConfig;

    constructor(config?: Partial<MessagingConfig>) {
        this.config = {
            slack: {
                webhookUrl: config?.slack?.webhookUrl || process.env.SLACK_WEBHOOK_URL || '',
                botToken: config?.slack?.botToken || process.env.SLACK_BOT_TOKEN || '',
                channel: config?.slack?.channel || process.env.SLACK_CHANNEL || '#security-alerts',
            },
            teams: {
                webhookUrl: config?.teams?.webhookUrl || process.env.TEAMS_WEBHOOK_URL || '',
            },
        };
    }

    /**
     * Check if Slack is configured.
     */
    isSlackConfigured(): boolean {
        return !!(this.config.slack?.webhookUrl || this.config.slack?.botToken);
    }

    /**
     * Check if Teams is configured.
     */
    isTeamsConfigured(): boolean {
        return !!this.config.teams?.webhookUrl;
    }

    /**
     * Send Slack message via webhook.
     */
    async sendSlackWebhook(message: SlackMessage): Promise<NotificationResult> {
        if (!this.config.slack?.webhookUrl) {
            return { success: false, error: 'Slack webhook not configured' };
        }

        try {
            const response = await fetchWithRetry<string>(
                this.config.slack.webhookUrl,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(message),
                }
            );

            if (response === '') {
                // Slack webhooks return empty string on success
                logger.info('[Messaging] Sent Slack webhook message');
                return { success: true };
            }

            return { success: false, error: 'Slack webhook failed' };
        } catch (error) {
            const message = (error as Error).message;
            logger.error(`[Messaging] Slack webhook failed: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * Send Slack message via API.
     */
    async sendSlackApi(message: SlackMessage): Promise<NotificationResult> {
        if (!this.config.slack?.botToken) {
            return { success: false, error: 'Slack bot token not configured' };
        }

        try {
            const response = await fetchJson<{ ok: boolean; ts: string; channel: string }>(
                'https://slack.com/api/chat.postMessage',
                {
                    method: 'POST',
                    headers: {
                        Authorization: `Bearer ${this.config.slack.botToken}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        channel: message.channel || this.config.slack.channel,
                        text: message.text,
                        blocks: message.blocks,
                        thread_ts: message.threadTs,
                        username: message.username,
                        icon_emoji: message.iconEmoji,
                    }),
                }
            );

            if (response?.ok) {
                logger.info(`[Messaging] Sent Slack API message to ${response.channel}`);
                return {
                    success: true,
                    messageId: response.ts,
                    threadTs: response.ts,
                };
            }

            return { success: false, error: 'Slack API returned ok: false' };
        } catch (error) {
            const message = (error as Error).message;
            logger.error(`[Messaging] Slack API failed: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * Send Teams card via webhook.
     */
    async sendTeamsCard(card: TeamsCard): Promise<NotificationResult> {
        if (!this.config.teams?.webhookUrl) {
            return { success: false, error: 'Teams webhook not configured' };
        }

        try {
            await fetchWithRetry(
                this.config.teams.webhookUrl,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(card),
                }
            );

            logger.info('[Messaging] Sent Teams card');
            return { success: true };
        } catch (error) {
            const message = (error as Error).message;
            logger.error(`[Messaging] Teams webhook failed: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * Send audit summary notification.
     */
    async sendAuditSummary(
        summary: {
            totalFindings: number;
            critical: number;
            high: number;
            medium: number;
            low: number;
            url: string;
            duration: number;
        },
        platform: 'slack' | 'teams' | 'both' = 'both'
    ): Promise<NotificationResult[]> {
        const results: NotificationResult[] = [];

        if ((platform === 'slack' || platform === 'both') && this.isSlackConfigured()) {
            const slackMessage = this.buildSlackAuditSummary(summary);
            const result = this.config.slack?.botToken
                ? await this.sendSlackApi(slackMessage)
                : await this.sendSlackWebhook(slackMessage);
            results.push(result);
        }

        if ((platform === 'teams' || platform === 'both') && this.isTeamsConfigured()) {
            const teamsCard = this.buildTeamsAuditSummary(summary);
            const result = await this.sendTeamsCard(teamsCard);
            results.push(result);
        }

        return results;
    }

    /**
     * Send finding notification (for critical/high findings).
     */
    async sendFindingNotification(
        finding: FindingForNotification,
        threadTs?: string
    ): Promise<NotificationResult> {
        // Only send critical and high findings
        if (finding.severity !== 'critical' && finding.severity !== 'high') {
            return { success: true, messageId: 'skipped-low-severity' };
        }

        if (this.isSlackConfigured()) {
            const slackMessage = this.buildSlackFinding(finding, threadTs);
            return this.config.slack?.botToken
                ? await this.sendSlackApi(slackMessage)
                : await this.sendSlackWebhook(slackMessage);
        }

        if (this.isTeamsConfigured()) {
            const teamsCard = this.buildTeamsFinding(finding);
            return await this.sendTeamsCard(teamsCard);
        }

        return { success: false, error: 'No messaging platform configured' };
    }

    /**
     * Send batch finding notifications.
     */
    async sendBatchFindings(
        findings: FindingForNotification[],
        options: { maxFindings?: number; threadTs?: string } = {}
    ): Promise<NotificationResult[]> {
        const maxFindings = options.maxFindings || 10;
        const criticalHigh = findings.filter(
            f => f.severity === 'critical' || f.severity === 'high'
        ).slice(0, maxFindings);

        const results: NotificationResult[] = [];
        let threadTs = options.threadTs;

        for (const finding of criticalHigh) {
            const result = await this.sendFindingNotification(finding, threadTs);
            results.push(result);

            // Use first message's thread for subsequent messages
            if (result.threadTs && !threadTs) {
                threadTs = result.threadTs;
            }

            // Small delay between messages to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        return results;
    }

    /**
     * Build Slack blocks for audit summary.
     */
    private buildSlackAuditSummary(summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        url: string;
        duration: number;
    }): SlackMessage {
        const color = summary.critical > 0 ? '#FF0000' : summary.high > 0 ? '#FF8C00' : '#36A64F';
        const emoji = summary.critical > 0 ? ':x:' : summary.high > 0 ? ':warning:' : ':white_check_mark:';

        return {
            text: `${emoji} Security Audit Complete: ${summary.url}`,
            blocks: [
                {
                    type: 'header',
                    text: {
                        type: 'plain_text',
                        text: `${emoji} Security Audit Complete`,
                    },
                },
                {
                    type: 'section',
                    text: {
                        type: 'mrkdwn',
                        text: `*Target:* ${summary.url}\n*Duration:* ${(summary.duration / 1000).toFixed(1)}s`,
                    },
                },
                {
                    type: 'section',
                    fields: [
                        {
                            type: 'mrkdwn',
                            text: `*Total Findings:*\n${summary.totalFindings}`,
                        },
                        {
                            type: 'mrkdwn',
                            text: `*Critical:*\n${summary.critical}`,
                        },
                        {
                            type: 'mrkdwn',
                            text: `*High:*\n${summary.high}`,
                        },
                        {
                            type: 'mrkdwn',
                            text: `*Medium:*\n${summary.medium}`,
                        },
                    ],
                },
                {
                    type: 'divider',
                },
            ],
        };
    }

    /**
     * Build Slack blocks for a finding.
     */
    private buildSlackFinding(finding: FindingForNotification, threadTs?: string): SlackMessage {
        const color = finding.severity === 'critical' ? '#FF0000' : '#FF8C00';
        const emoji = finding.severity === 'critical' ? ':x:' : ':warning:';

        const blocks: SlackBlock[] = [
            {
                type: 'section',
                text: {
                    type: 'mrkdwn',
                    text: `${emoji} *${finding.type}* (${finding.severity.toUpperCase()})`,
                },
            },
            {
                type: 'section',
                text: {
                    type: 'mrkdwn',
                    text: finding.message,
                },
            },
        ];

        if (finding.url) {
            blocks.push({
                type: 'context',
                elements: [
                    {
                        type: 'mrkdwn',
                        text: `URL: ${finding.url}`,
                    },
                ],
            });
        }

        return {
            text: `${emoji} ${finding.type}: ${finding.message.slice(0, 100)}`,
            blocks,
            threadTs,
            iconEmoji: emoji,
        };
    }

    /**
     * Build Teams card for audit summary.
     */
    private buildTeamsAuditSummary(summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        url: string;
        duration: number;
    }): TeamsCard {
        const themeColor = summary.critical > 0 ? 'FF0000' : summary.high > 0 ? 'FF8C00' : '36A64F';

        return {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            themeColor,
            summary: `Security Audit: ${summary.totalFindings} findings`,
            sections: [
                {
                    activityTitle: 'Security Audit Complete',
                    activitySubtitle: summary.url,
                    facts: [
                        { name: 'Duration', value: `${(summary.duration / 1000).toFixed(1)}s` },
                        { name: 'Total Findings', value: String(summary.totalFindings) },
                        { name: 'Critical', value: String(summary.critical) },
                        { name: 'High', value: String(summary.high) },
                        { name: 'Medium', value: String(summary.medium) },
                        { name: 'Low', value: String(summary.low) },
                    ],
                },
            ],
        };
    }

    /**
     * Build Teams card for a finding.
     */
    private buildTeamsFinding(finding: FindingForNotification): TeamsCard {
        const themeColor = finding.severity === 'critical' ? 'FF0000' : 'FF8C00';

        const facts: Array<{ name: string; value: string }> = [
            { name: 'Severity', value: finding.severity.toUpperCase() },
            { name: 'Type', value: finding.type },
        ];

        if (finding.url) {
            facts.push({ name: 'URL', value: finding.url });
        }

        if (finding.file) {
            facts.push({
                name: 'Location',
                value: `${finding.file}${finding.line ? `:${finding.line}` : ''}`,
            });
        }

        return {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            themeColor,
            summary: `${finding.type}: ${finding.message.slice(0, 50)}`,
            sections: [
                {
                    activityTitle: `${finding.type} (${finding.severity.toUpperCase()})`,
                    text: finding.message,
                    facts,
                },
            ],
        };
    }
}

export default MessagingIntegrationService;
