import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';
import { createConfig } from '../config/compliance.config';
import { getComplianceTags } from '../data/compliance-map';

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
}

/**
 * SIEM Logger Service
 * Forwards security findings to SIEM systems (Splunk/Datadog)
 */
export class SiemLogger {

    /**
     * Log a single vulnerability finding
     */
    static async logVulnerability(issue: SecurityIssue): Promise<void> {
        const config = createConfig();

        // 1. Safe Check
        if (!config.siem || !config.siem.enabled) {
            return;
        }

        // 2. Format Event (ECS/OCSF style)
        const event = {
            timestamp: issue.timestamp || new Date().toISOString(),
            event_type: 'vulnerability_detected',
            severity: issue.severity.toUpperCase(),
            rule_id: issue.id,
            target_url: issue.targetUrl,
            remediation_status: issue.remediation_status || 'open',
            compliance_tags: issue.complianceTags && issue.complianceTags.length > 0
                ? issue.complianceTags
                : getComplianceTags(issue.id)
        };

        const logLine = JSON.stringify(event);

        // 3. Output 1: File Logging (Splunk Monitor Input)
        try {
            const logPath = config.siem.logFilePath ? path.resolve(config.siem.logFilePath) : path.resolve('logs/security-events.log');
            const logDir = path.dirname(logPath);

            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }

            fs.appendFileSync(logPath, logLine + '\n', 'utf8');
            // logger.debug(`SIEM Event written to ${logPath}`); // Verbose
        } catch (error) {
            logger.error(`Failed to write SIEM log to file: ${error}`);
        }

        // 4. Output 2: HTTP Webhook (Splunk HEC / Datadog)
        if (config.siem.webhookUrl && config.siem.webhookUrl.trim() !== '') {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

                await fetch(config.siem.webhookUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Splunk ${process.env.SIEM_TOKEN || ''}` // Optional token usage pattern
                    },
                    body: logLine,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);
            } catch (error) {
                // Silent fail for webhook to avoid spamming logs if SIEM is down
                // logger.debug(`SIEM Webhook failed: ${error}`);
            }
        }
    }
}
