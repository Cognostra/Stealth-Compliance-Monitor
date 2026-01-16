import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger.js';
import { createConfig } from '../config/compliance.config.js';
import { getComplianceTags } from '../data/compliance-map.js';

/**
 * Interface definition for a generic security issue
 * Maps to ArchitectIssue and other finding types
 */
export interface SecurityIssue {
    id: string;
    severity: string;  // critical, high, medium, low
    description?: string;
    targetUrl: string; // The specific page URL
    timestamp?: string; // ISO string
    remediation_status?: string;
    complianceTags?: string[];
    /** Optional CVE ID */
    cveId?: string;
    /** Optional CVSS score */
    cvssScore?: number;
    /** Category of the issue */
    category?: string;
    /** Source of the finding */
    source?: string;
}

/**
 * ECS (Elastic Common Schema) compatible event
 */
export interface EcsEvent {
    '@timestamp': string;
    event: {
        kind: string;
        category: string[];
        type: string[];
        severity: number;
        outcome?: string;
        action?: string;
        dataset?: string;
        module?: string;
    };
    rule?: {
        id: string;
        name?: string;
        category?: string;
        description?: string;
    };
    vulnerability?: {
        id?: string;
        severity?: string;
        score?: {
            base?: number;
            version?: string;
        };
        category?: string[];
    };
    url?: {
        full?: string;
        domain?: string;
        path?: string;
    };
    host?: {
        name?: string;
    };
    tags?: string[];
    labels?: Record<string, string>;
    message?: string;
}

/**
 * Batch of events for bulk logging
 */
export interface EventBatch {
    events: EcsEvent[];
    metadata: {
        scanId: string;
        targetUrl: string;
        timestamp: string;
        eventCount: number;
    };
}

/**
 * SIEM Logger Service
 * Forwards security findings to SIEM systems (Splunk/Datadog/Elastic)
 * Supports ECS (Elastic Common Schema) and OCSF formats
 */
export class SiemLogger {
    private static eventBuffer: EcsEvent[] = [];
    private static readonly BUFFER_SIZE = 50;
    private static flushTimer: NodeJS.Timeout | null = null;
    private static readonly FLUSH_INTERVAL_MS = 5000;

    /**
     * Initialize the SIEM logger with auto-flush
     */
    static initialize(): void {
        if (!SiemLogger.flushTimer) {
            SiemLogger.flushTimer = setInterval(() => {
                SiemLogger.flush().catch(err => logger.error(`SIEM flush error: ${err}`));
            }, SiemLogger.FLUSH_INTERVAL_MS);
        }
    }

    /**
     * Shutdown the SIEM logger
     */
    static async shutdown(): Promise<void> {
        if (SiemLogger.flushTimer) {
            clearInterval(SiemLogger.flushTimer);
            SiemLogger.flushTimer = null;
        }
        await SiemLogger.flush();
    }

    /**
     * Map severity string to numeric value (1-4)
     */
    private static mapSeverityToNumber(severity: string): number {
        switch (severity.toLowerCase()) {
            case 'critical': return 4;
            case 'high': return 3;
            case 'medium': return 2;
            case 'low': return 1;
            default: return 0;
        }
    }

    /**
     * Convert a SecurityIssue to ECS format
     */
    static toEcsFormat(issue: SecurityIssue): EcsEvent {
        const urlObj = issue.targetUrl ? (() => {
            try {
                return new URL(issue.targetUrl);
            } catch {
                return null;
            }
        })() : null;

        const event: EcsEvent = {
            '@timestamp': issue.timestamp || new Date().toISOString(),
            event: {
                kind: 'alert',
                category: ['vulnerability', 'web'],
                type: ['indicator'],
                severity: SiemLogger.mapSeverityToNumber(issue.severity),
                dataset: 'compliance_monitor.vulnerability',
                module: 'stealth_compliance_monitor',
            },
            rule: {
                id: issue.id,
                name: issue.id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
                category: issue.category || 'security',
                description: issue.description,
            },
            tags: issue.complianceTags || getComplianceTags(issue.id),
            message: `[${issue.severity.toUpperCase()}] ${issue.id}: ${issue.description || 'Security issue detected'}`,
        };

        // Add URL info if available
        if (urlObj) {
            event.url = {
                full: issue.targetUrl,
                domain: urlObj.hostname,
                path: urlObj.pathname,
            };
            event.host = {
                name: urlObj.hostname,
            };
        }

        // Add vulnerability info if CVE is present
        if (issue.cveId) {
            event.vulnerability = {
                id: issue.cveId,
                severity: issue.severity.toUpperCase(),
                category: issue.complianceTags || [],
            };
            if (issue.cvssScore) {
                event.vulnerability.score = {
                    base: issue.cvssScore,
                    version: '3.1',
                };
            }
        }

        // Add labels for filtering
        event.labels = {
            remediation_status: issue.remediation_status || 'open',
            source: issue.source || 'compliance_scanner',
        };

        return event;
    }

    /**
     * Log a single vulnerability finding (buffered)
     */
    static async logVulnerability(issue: SecurityIssue): Promise<void> {
        const config = createConfig();

        // Safe Check
        if (!config.siem || !config.siem.enabled) {
            return;
        }

        const ecsEvent = SiemLogger.toEcsFormat(issue);
        SiemLogger.eventBuffer.push(ecsEvent);

        // Flush if buffer is full
        if (SiemLogger.eventBuffer.length >= SiemLogger.BUFFER_SIZE) {
            await SiemLogger.flush();
        }
    }

    /**
     * Log multiple vulnerabilities at once
     */
    static async logBatch(issues: SecurityIssue[]): Promise<void> {
        const config = createConfig();

        if (!config.siem || !config.siem.enabled) {
            return;
        }

        for (const issue of issues) {
            const ecsEvent = SiemLogger.toEcsFormat(issue);
            SiemLogger.eventBuffer.push(ecsEvent);
        }

        // Flush after batch
        await SiemLogger.flush();
    }

    /**
     * Flush buffered events to file and webhook
     */
    static async flush(): Promise<void> {
        if (SiemLogger.eventBuffer.length === 0) {
            return;
        }

        const config = createConfig();
        const events = [...SiemLogger.eventBuffer];
        SiemLogger.eventBuffer = [];

        // Write to file (NDJSON format for Splunk/Elastic ingestion)
        const logPath = config.siem?.logFilePath 
            ? path.resolve(config.siem.logFilePath) 
            : path.resolve('logs/security-events.log');
        
        try {
            const logDir = path.dirname(logPath);
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }

            // Append each event as a separate JSON line (NDJSON)
            const ndjson = events.map(e => JSON.stringify(e)).join('\n') + '\n';
            fs.appendFileSync(logPath, ndjson, 'utf8');
            
            logger.debug(`SIEM: Wrote ${events.length} events to ${logPath}`);
        } catch (error) {
            logger.error(`Failed to write SIEM log to file: ${error}`);
        }

        // Send to webhook if configured
        if (config.siem?.webhookUrl) {
            await SiemLogger.sendToWebhook(events, config.siem.webhookUrl);
        }
    }

    /**
     * Send events to SIEM webhook (Splunk HEC, Datadog, etc.)
     */
    private static async sendToWebhook(events: EcsEvent[], webhookUrl: string): Promise<void> {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);

            // Detect endpoint type and format accordingly
            const isSplunkHec = webhookUrl.includes('/services/collector');
            const isDatadog = webhookUrl.includes('datadoghq.com');

            let body: string;
            let headers: Record<string, string> = {
                'Content-Type': 'application/json',
            };

            if (isSplunkHec) {
                // Splunk HEC format
                const splunkEvents = events.map(e => ({
                    time: new Date(e['@timestamp']).getTime() / 1000,
                    host: e.host?.name || 'compliance-monitor',
                    source: 'stealth-compliance-monitor',
                    sourcetype: '_json',
                    event: e,
                }));
                body = splunkEvents.map(e => JSON.stringify(e)).join('');
                
                // Add Splunk HEC token if available
                const token = process.env.SIEM_TOKEN || process.env.SPLUNK_HEC_TOKEN;
                if (token) {
                    headers['Authorization'] = `Splunk ${token}`;
                }
            } else if (isDatadog) {
                // Datadog Logs API format
                const datadogEvents = events.map(e => ({
                    ddsource: 'compliance-monitor',
                    ddtags: `env:${process.env.NODE_ENV || 'production'},service:stealth-compliance-monitor`,
                    hostname: e.host?.name || 'compliance-monitor',
                    message: e.message,
                    status: e.event.severity >= 3 ? 'error' : e.event.severity >= 2 ? 'warning' : 'info',
                    ...e,
                }));
                body = JSON.stringify(datadogEvents);
                
                const apiKey = process.env.DD_API_KEY || process.env.DATADOG_API_KEY;
                if (apiKey) {
                    headers['DD-API-KEY'] = apiKey;
                }
            } else {
                // Generic JSON format
                body = JSON.stringify({
                    events,
                    metadata: {
                        source: 'stealth-compliance-monitor',
                        timestamp: new Date().toISOString(),
                        count: events.length,
                    },
                });
            }

            const response = await fetch(webhookUrl, {
                method: 'POST',
                headers,
                body,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                logger.debug(`SIEM: Sent ${events.length} events to webhook`);
            } else {
                logger.warn(`SIEM webhook failed: ${response.status} ${response.statusText}`);
            }
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            if (!errMsg.includes('aborted')) {
                logger.warn(`SIEM webhook error: ${errMsg}`);
            }
        }
    }

    /**
     * Log a scan completion event
     */
    static async logScanCompletion(scanResult: {
        targetUrl: string;
        duration: number;
        passed: boolean;
        criticalCount: number;
        highCount: number;
        scanId?: string;
    }): Promise<void> {
        const config = createConfig();

        if (!config.siem || !config.siem.enabled) {
            return;
        }

        const event: EcsEvent = {
            '@timestamp': new Date().toISOString(),
            event: {
                kind: 'event',
                category: ['process'],
                type: ['end'],
                severity: scanResult.criticalCount > 0 ? 4 : scanResult.highCount > 0 ? 3 : 1,
                outcome: scanResult.passed ? 'success' : 'failure',
                action: 'scan_completed',
                dataset: 'compliance_monitor.scan',
                module: 'stealth_compliance_monitor',
            },
            url: {
                full: scanResult.targetUrl,
            },
            tags: ['scan-result', scanResult.passed ? 'passed' : 'failed'],
            labels: {
                scan_id: scanResult.scanId || `scan-${Date.now()}`,
                duration_ms: String(scanResult.duration),
                critical_count: String(scanResult.criticalCount),
                high_count: String(scanResult.highCount),
            },
            message: `Scan completed for ${scanResult.targetUrl}: ${scanResult.passed ? 'PASSED' : 'FAILED'} (${scanResult.criticalCount} critical, ${scanResult.highCount} high)`,
        };

        SiemLogger.eventBuffer.push(event);
        await SiemLogger.flush();
    }

    /**
     * Log an authentication event
     */
    static async logAuthEvent(authResult: {
        targetUrl: string;
        success: boolean;
        method?: string;
        duration?: number;
        error?: string;
    }): Promise<void> {
        const config = createConfig();

        if (!config.siem || !config.siem.enabled) {
            return;
        }

        const event: EcsEvent = {
            '@timestamp': new Date().toISOString(),
            event: {
                kind: 'event',
                category: ['authentication'],
                type: [authResult.success ? 'allowed' : 'denied'],
                severity: authResult.success ? 1 : 2,
                outcome: authResult.success ? 'success' : 'failure',
                action: 'user_login',
                dataset: 'compliance_monitor.auth',
                module: 'stealth_compliance_monitor',
            },
            url: {
                full: authResult.targetUrl,
            },
            tags: ['authentication', authResult.method || 'standard'],
            labels: {
                auth_method: authResult.method || 'standard',
            },
            message: `Authentication ${authResult.success ? 'succeeded' : 'failed'} for ${authResult.targetUrl}${authResult.error ? `: ${authResult.error}` : ''}`,
        };

        SiemLogger.eventBuffer.push(event);
    }

    /**
     * Get buffered event count (for testing)
     */
    static getBufferedCount(): number {
        return SiemLogger.eventBuffer.length;
    }

    /**
     * Clear buffer (for testing)
     */
    static clearBuffer(): void {
        SiemLogger.eventBuffer = [];
    }
}
