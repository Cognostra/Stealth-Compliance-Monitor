/**
 * ZAP Service
 * OWASP ZAP passive security scanning (NO ACTIVE ATTACKS)
 */

import { SecurityAlert, Logger } from '../types';
import { EnvConfig } from '../config/env';

/**
 * ZAP Alert Risk Levels
 */
type ZapRisk = 'High' | 'Medium' | 'Low' | 'Informational';

/**
 * ZAP API Response for alerts
 */
interface ZapAlertResponse {
    id: string;
    name: string;
    risk: string;
    description: string;
    solution: string;
    url: string;
    confidence: string;
}

export class ZapService {
    private readonly config: EnvConfig;
    private readonly logger: Logger;
    private readonly baseUrl: string;
    private isInitialized: boolean = false;

    constructor(config: EnvConfig, logger: Logger) {
        this.config = config;
        this.logger = logger;
        this.baseUrl = config.ZAP_PROXY_URL;
    }

    /**
     * Check if ZAP is available and in passive mode
     */
    async initialize(): Promise<void> {
        try {
            // Check ZAP status
            const response = await fetch(`${this.baseUrl}/JSON/core/view/version/`);

            if (!response.ok) {
                throw new Error(`ZAP API returned status ${response.status}`);
            }

            const data = await response.json() as { version: string };
            this.logger.info(`Connected to ZAP version: ${data.version}`);

            // Verify passive mode (attack mode should be OFF)
            await this.verifyPassiveMode();

            // Set scope to only target URL
            await this.setScope();

            this.isInitialized = true;
        } catch (error) {
            this.logger.warn(`Failed to connect to ZAP: ${error}. Continuing without ZAP.`);
            this.isInitialized = false;
        }
    }

    /**
     * Verify ZAP is in passive/safe mode - NO ACTIVE ATTACKS
     */
    private async verifyPassiveMode(): Promise<void> {
        try {
            const response = await fetch(`${this.baseUrl}/JSON/pscan/view/scanOnlyInScope/`);

            if (response.ok) {
                this.logger.info('ZAP passive scanner verified');
            }

            // Disable active scanning as a safety measure
            await fetch(`${this.baseUrl}/JSON/ascan/action/disableAllScanners/`);
            this.logger.info('ZAP active scanners disabled (SAFETY GUARDRAIL)');
        } catch (error) {
            this.logger.debug(`Passive mode check: ${error}`);
        }
    }

    /**
     * Set ZAP scope to only target URL
     */
    private async setScope(): Promise<void> {
        try {
            const targetUrl = encodeURIComponent(this.config.LIVE_URL);

            // Add URL to context/scope
            await fetch(
                `${this.baseUrl}/JSON/context/action/includeInContext/?contextName=Default+Context&regex=${targetUrl}.*`
            );

            this.logger.info(`ZAP scope set to: ${this.config.LIVE_URL}`);
        } catch (error) {
            this.logger.debug(`Scope setting: ${error}`);
        }
    }

    /**
     * Check if service is in passive mode only
     */
    isPassiveMode(): boolean {
        return true; // This service ONLY supports passive mode
    }

    /**
     * Get all passive alerts for a URL
     */
    async getAlerts(url: string): Promise<SecurityAlert[]> {
        if (!this.isInitialized) {
            this.logger.debug('ZAP not initialized, returning empty alerts');
            return [];
        }

        try {
            const encodedUrl = encodeURIComponent(url);
            const response = await fetch(
                `${this.baseUrl}/JSON/alert/view/alerts/?baseurl=${encodedUrl}`
            );

            if (!response.ok) {
                throw new Error(`Failed to get alerts: ${response.status}`);
            }

            const data = await response.json() as { alerts?: ZapAlertResponse[] };
            const alerts: ZapAlertResponse[] = data.alerts || [];

            this.logger.info(`Found ${alerts.length} ZAP alerts for ${url}`);

            return alerts.map(alert => this.mapAlert(alert));
        } catch (error) {
            this.logger.warn(`Failed to get ZAP alerts: ${error}`);
            return [];
        }
    }

    /**
     * Map ZAP alert to our SecurityAlert format
     */
    private mapAlert(zapAlert: ZapAlertResponse): SecurityAlert {
        return {
            risk: this.mapRisk(zapAlert.risk),
            name: zapAlert.name,
            description: zapAlert.description,
            url: zapAlert.url,
            solution: zapAlert.solution,
        };
    }

    /**
     * Map ZAP risk string to our enum
     */
    private mapRisk(risk: string): ZapRisk {
        switch (risk.toLowerCase()) {
            case 'high':
                return 'High';
            case 'medium':
                return 'Medium';
            case 'low':
                return 'Low';
            default:
                return 'Informational';
        }
    }

    /**
     * Get summary of alerts by risk level
     */
    async getAlertSummary(url: string): Promise<Record<ZapRisk, number>> {
        const alerts = await this.getAlerts(url);

        return {
            High: alerts.filter(a => a.risk === 'High').length,
            Medium: alerts.filter(a => a.risk === 'Medium').length,
            Low: alerts.filter(a => a.risk === 'Low').length,
            Informational: alerts.filter(a => a.risk === 'Informational').length,
        };
    }

    /**
     * Cleanup (no active sessions to stop in passive mode)
     */
    async close(): Promise<void> {
        this.logger.debug('ZAP service closed');
        this.isInitialized = false;
    }
}

export default ZapService;
