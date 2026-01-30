/**
 * Ticketing Integration Service
 *
 * Integrates with JIRA and ServiceNow for creating and managing
 * tickets from audit findings.
 *
 * Features:
 * - JIRA REST API integration
 * - ServiceNow Table API integration
 * - Automatic ticket creation from findings
 * - Severity mapping to priority
 * - Custom field mapping
 */

import { logger } from '../../utils/logger.js';
import { fetchJson, fetchWithRetry } from '../../utils/api-client.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface TicketingConfig {
    jira?: {
        baseUrl: string;
        username: string;
        apiToken: string;
        projectKey: string;
    };
    servicenow?: {
        instance: string;
        username: string;
        password: string;
        table: string;
    };
}

export interface JiraIssue {
    key?: string;
    fields: {
        summary: string;
        description?: string;
        issuetype: { name: string };
        priority?: { name: string };
        labels?: string[];
        components?: Array<{ name: string }>;
        assignee?: { accountId: string };
        [key: string]: unknown;
    };
}

export interface ServiceNowTicket {
    short_description: string;
    description?: string;
    priority?: string;
    category?: string;
    subcategory?: string;
    assignment_group?: string;
    assigned_to?: string;
    u_security_finding?: boolean;
    [key: string]: unknown;
}

export interface FindingForTicket {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    message: string;
    url?: string;
    file?: string;
    line?: number;
    remediation?: string;
}

export interface TicketResult {
    success: boolean;
    ticketId?: string;
    ticketUrl?: string;
    error?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class TicketingIntegrationService {
    private config: TicketingConfig;

    constructor(config?: Partial<TicketingConfig>) {
        this.config = {
            jira: {
                baseUrl: config?.jira?.baseUrl || process.env.JIRA_BASE_URL || '',
                username: config?.jira?.username || process.env.JIRA_USERNAME || '',
                apiToken: config?.jira?.apiToken || process.env.JIRA_API_TOKEN || '',
                projectKey: config?.jira?.projectKey || process.env.JIRA_PROJECT_KEY || '',
            },
            servicenow: {
                instance: config?.servicenow?.instance || process.env.SERVICENOW_INSTANCE || '',
                username: config?.servicenow?.username || process.env.SERVICENOW_USERNAME || '',
                password: config?.servicenow?.password || process.env.SERVICENOW_PASSWORD || '',
                table: config?.servicenow?.table || process.env.SERVICENOW_TABLE || 'incident',
            },
        };
    }

    /**
     * Check if JIRA integration is configured.
     */
    isJiraConfigured(): boolean {
        return !!(
            this.config.jira?.baseUrl &&
            this.config.jira?.username &&
            this.config.jira?.apiToken &&
            this.config.jira?.projectKey
        );
    }

    /**
     * Check if ServiceNow integration is configured.
     */
    isServiceNowConfigured(): boolean {
        return !!(
            this.config.servicenow?.instance &&
            this.config.servicenow?.username &&
            this.config.servicenow?.password
        );
    }

    /**
     * Create JIRA issue from finding.
     */
    async createJiraIssue(finding: FindingForTicket): Promise<TicketResult> {
        if (!this.isJiraConfigured()) {
            return { success: false, error: 'JIRA not configured' };
        }

        try {
            const issue: JiraIssue = {
                fields: {
                    summary: `[Security] ${finding.type}: ${finding.message.slice(0, 50)}`,
                    description: this.generateJiraDescription(finding),
                    issuetype: { name: 'Bug' },
                    priority: { name: this.mapSeverityToJiraPriority(finding.severity) },
                    labels: ['security', 'stealth-compliance', finding.type],
                },
            };

            const auth = Buffer.from(
                `${this.config.jira!.username}:${this.config.jira!.apiToken}`
            ).toString('base64');

            const response = await fetchJson<{ key: string; self: string }>(
                `${this.config.jira!.baseUrl}/rest/api/2/issue`,
                {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${auth}`,
                        'Content-Type': 'application/json',
                        Accept: 'application/json',
                    },
                    body: JSON.stringify(issue),
                }
            );

            if (response) {
                logger.info(`[Ticketing] Created JIRA issue ${response.key}`);
                return {
                    success: true,
                    ticketId: response.key,
                    ticketUrl: `${this.config.jira!.baseUrl}/browse/${response.key}`,
                };
            }

            return { success: false, error: 'Failed to create JIRA issue' };
        } catch (error) {
            const message = (error as Error).message;
            logger.error(`[Ticketing] Failed to create JIRA issue: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * Create ServiceNow ticket from finding.
     */
    async createServiceNowTicket(finding: FindingForTicket): Promise<TicketResult> {
        if (!this.isServiceNowConfigured()) {
            return { success: false, error: 'ServiceNow not configured' };
        }

        try {
            const ticket: ServiceNowTicket = {
                short_description: `[Security] ${finding.type}: ${finding.message.slice(0, 80)}`,
                description: this.generateServiceNowDescription(finding),
                priority: this.mapSeverityToServiceNowPriority(finding.severity),
                category: 'Security',
                subcategory: 'Vulnerability',
                u_security_finding: true,
            };

            const auth = Buffer.from(
                `${this.config.servicenow!.username}:${this.config.servicenow!.password}`
            ).toString('base64');

            const response = await fetchJson<{ result: { sys_id: string; number: string } }>(
                `https://${this.config.servicenow!.instance}.service-now.com/api/now/table/${this.config.servicenow!.table}`,
                {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${auth}`,
                        'Content-Type': 'application/json',
                        Accept: 'application/json',
                    },
                    body: JSON.stringify(ticket),
                }
            );

            if (response?.result) {
                logger.info(`[Ticketing] Created ServiceNow ticket ${response.result.number}`);
                return {
                    success: true,
                    ticketId: response.result.number,
                    ticketUrl: `https://${this.config.servicenow!.instance}.service-now.com/nav_to.do?uri=incident.do?sys_id=${response.result.sys_id}`,
                };
            }

            return { success: false, error: 'Failed to create ServiceNow ticket' };
        } catch (error) {
            const message = (error as Error).message;
            logger.error(`[Ticketing] Failed to create ServiceNow ticket: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * Batch create tickets from multiple findings.
     */
    async batchCreateTickets(
        findings: FindingForTicket[],
        options: { dryRun?: boolean; maxTickets?: number } = {}
    ): Promise<TicketResult[]> {
        const results: TicketResult[] = [];
        const maxTickets = options.maxTickets || 50;
        const limitedFindings = findings.slice(0, maxTickets);

        logger.info(`[Ticketing] Creating ${limitedFindings.length} tickets from findings`);

        for (const finding of limitedFindings) {
            if (options.dryRun) {
                results.push({
                    success: true,
                    ticketId: 'DRY-RUN',
                    ticketUrl: '#',
                });
                continue;
            }

            // Prefer JIRA if configured, fallback to ServiceNow
            if (this.isJiraConfigured()) {
                const result = await this.createJiraIssue(finding);
                results.push(result);
            } else if (this.isServiceNowConfigured()) {
                const result = await this.createServiceNowTicket(finding);
                results.push(result);
            } else {
                results.push({
                    success: false,
                    error: 'No ticketing system configured',
                });
            }

            // Rate limiting: wait between tickets
            await new Promise(resolve => setTimeout(resolve, 500));
        }

        const successful = results.filter(r => r.success).length;
        logger.info(`[Ticketing] Created ${successful}/${results.length} tickets successfully`);

        return results;
    }

    /**
     * Link tickets together (for related findings).
     */
    async linkJiraIssues(issueKey1: string, issueKey2: string, linkType: string = 'relates to'): Promise<boolean> {
        if (!this.isJiraConfigured()) {
            return false;
        }

        try {
            const auth = Buffer.from(
                `${this.config.jira!.username}:${this.config.jira!.apiToken}`
            ).toString('base64');

            await fetchJson(
                `${this.config.jira!.baseUrl}/rest/api/2/issueLink`,
                {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${auth}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        type: { name: linkType },
                        inwardIssue: { key: issueKey1 },
                        outwardIssue: { key: issueKey2 },
                    }),
                }
            );

            logger.info(`[Ticketing] Linked ${issueKey1} to ${issueKey2}`);
            return true;
        } catch (error) {
            logger.error(`[Ticketing] Failed to link issues: ${(error as Error).message}`);
            return false;
        }
    }

    /**
     * Get JIRA project info.
     */
    async getJiraProjectInfo(): Promise<{ key: string; name: string; issueTypes: string[] } | null> {
        if (!this.isJiraConfigured()) {
            return null;
        }

        try {
            const auth = Buffer.from(
                `${this.config.jira!.username}:${this.config.jira!.apiToken}`
            ).toString('base64');

            const response = await fetchWithRetry<{
                key: string;
                name: string;
                issueTypes: Array<{ name: string }>;
            }>(
                `${this.config.jira!.baseUrl}/rest/api/2/project/${this.config.jira!.projectKey}`,
                {
                    method: 'GET',
                    headers: {
                        Authorization: `Basic ${auth}`,
                        Accept: 'application/json',
                    },
                }
            );

            if (response) {
                return {
                    key: response.key,
                    name: response.name,
                    issueTypes: response.issueTypes.map(t => t.name),
                };
            }

            return null;
        } catch (error) {
            logger.error(`[Ticketing] Failed to get project info: ${(error as Error).message}`);
            return null;
        }
    }

    private generateJiraDescription(finding: FindingForTicket): string {
        const lines = [
            `h2. Security Finding: ${finding.type}`,
            '',
            '*Severity:* ${finding.severity.toUpperCase()}',
            '',
            '*Description:*',
            finding.message,
            '',
        ];

        if (finding.url) {
            lines.push(`*URL:* ${finding.url}`, '');
        }

        if (finding.file) {
            lines.push(`*Location:* ${finding.file}${finding.line ? `:${finding.line}` : ''}`, '');
        }

        if (finding.remediation) {
            lines.push('*Remediation:*', finding.remediation, '');
        }

        lines.push(
            '----',
            '_This issue was automatically generated by Stealth Compliance Scanner_'
        );

        return lines.join('\n');
    }

    private generateServiceNowDescription(finding: FindingForTicket): string {
        const lines = [
            `Security Finding: ${finding.type}`,
            '',
            `Severity: ${finding.severity.toUpperCase()}`,
            '',
            'Description:',
            finding.message,
            '',
        ];

        if (finding.url) {
            lines.push(`URL: ${finding.url}`, '');
        }

        if (finding.file) {
            lines.push(`Location: ${finding.file}${finding.line ? `:${finding.line}` : ''}`, '');
        }

        if (finding.remediation) {
            lines.push('Remediation:', finding.remediation, '');
        }

        lines.push(
            '---',
            'This incident was automatically generated by Stealth Compliance Scanner'
        );

        return lines.join('\n');
    }

    private mapSeverityToJiraPriority(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'Highest';
            case 'high':
                return 'High';
            case 'medium':
                return 'Medium';
            case 'low':
                return 'Low';
            default:
                return 'Lowest';
        }
    }

    private mapSeverityToServiceNowPriority(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
                return '1';
            case 'high':
                return '2';
            case 'medium':
                return '3';
            case 'low':
                return '4';
            default:
                return '5';
        }
    }
}

export default TicketingIntegrationService;
