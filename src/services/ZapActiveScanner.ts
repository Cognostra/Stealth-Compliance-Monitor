/**
 * ZAP Active Scanner Service
 * 
 * Extends ZAP capabilities with active scanning (spider + active scan).
 * 
 * ⚠️ WARNING: ACTIVE SCANNING IS AGGRESSIVE ⚠️
 * - May trigger WAF/IDS alerts
 * - May cause server load
 * - Only use with explicit permission
 * - Only on systems you own or have authorized access to
 * 
 * Features:
 * - Spider crawling to discover URLs
 * - Active vulnerability scanning with ZAP attack policies
 * - Progress monitoring with timeouts
 * - Heavy rate limiting between scan phases
 */

import { SecurityAlert, Logger } from '../types/index.js';
import { EnvConfig } from '../config/env.js';
import { retryNetwork } from '../utils/retry.js';
import { sleep, humanDelay } from '../utils/throttle.js';

/**
 * Active scan progress status
 */
export interface ActiveScanProgress {
    scanId: string;
    status: 'running' | 'completed' | 'failed';
    progress: number; // 0-100
    alertsFound: number;
}

/**
 * Spider scan progress status
 */
export interface SpiderProgress {
    scanId: string;
    status: 'running' | 'completed' | 'failed';
    progress: number; // 0-100
    urlsFound: number;
}

/**
 * Active scan result with alerts categorized by source
 */
export interface ActiveScanResult {
    spiderUrls: string[];
    passiveAlerts: SecurityAlert[];
    activeAlerts: SecurityAlert[];
    duration: number;
    completed: boolean;
}

/**
 * ZAP Alert Risk Levels
 */
type ZapRisk = 'High' | 'Medium' | 'Low' | 'Informational';

/**
 * ZAP API Response for alerts
 */
interface ZapAlertResponse {
    id: string;
    alertRef: string;
    name: string;
    risk: string;
    description: string;
    solution: string;
    url: string;
    confidence: string;
    sourceid?: string;
    method?: string;
    attack?: string;
    evidence?: string;
}

export class ZapActiveScanner {
    private readonly config: EnvConfig;
    private readonly logger: Logger;
    private readonly baseUrl: string;
    private readonly apiKey: string | undefined;
    private isInitialized: boolean = false;

    // Rate limiting defaults (aggressive for safety)
    private readonly SPIDER_DELAY_MS = 5000;
    private readonly ACTIVE_SCAN_DELAY_MS = 10000;
    private readonly POLL_INTERVAL_MS = 3000;
    private readonly SPIDER_TIMEOUT_MS = 300000; // 5 minutes
    private readonly ACTIVE_SCAN_TIMEOUT_MS = 600000; // 10 minutes

    constructor(config: EnvConfig, logger: Logger) {
        this.config = config;
        this.logger = logger;
        this.baseUrl = config.ZAP_PROXY_URL;
        this.apiKey = config.ZAP_API_KEY;
    }

    /**
     * Build ZAP API URL with optional API key parameter
     */
    private buildUrl(endpoint: string, params: Record<string, string> = {}): string {
        const url = new URL(endpoint, this.baseUrl);

        if (this.apiKey) {
            url.searchParams.set('apikey', this.apiKey);
        }

        for (const [key, value] of Object.entries(params)) {
            url.searchParams.set(key, value);
        }

        return url.toString();
    }

    /**
     * Initialize the active scanner
     */
    async initialize(): Promise<boolean> {
        try {
            // Check ZAP status
            const response = await retryNetwork(
                () => fetch(this.buildUrl('/JSON/core/view/version/')),
                { retries: 3, baseDelay: 2000 }
            );

            if (!response.ok) {
                throw new Error(`ZAP API returned status ${response.status}`);
            }

            const data = await response.json() as { version: string };
            this.logger.info(`[ACTIVE] Connected to ZAP version: ${data.version}`);

            // Set scope to target URL
            await this.setScope();

            // Enable all scanners for active mode
            await this.enableScanners();

            this.isInitialized = true;
            return true;
        } catch (error) {
            this.logger.error(`[ACTIVE] Failed to initialize: ${error}`);
            this.isInitialized = false;
            return false;
        }
    }

    /**
     * Set ZAP scope to target URL for active scanning
     */
    private async setScope(): Promise<void> {
        try {
            const targetUrl = this.config.LIVE_URL;

            // Include target in scope
            await fetch(
                this.buildUrl('/JSON/context/action/includeInContext/', {
                    contextName: 'Default Context',
                    regex: `${targetUrl}.*`
                })
            );

            this.logger.info(`[ACTIVE] Scope set to: ${targetUrl}`);
        } catch (error) {
            this.logger.warn(`[ACTIVE] Failed to set scope: ${error}`);
        }
    }

    /**
     * Enable all ZAP active scanners
     */
    private async enableScanners(): Promise<void> {
        try {
            await fetch(this.buildUrl('/JSON/ascan/action/enableAllScanners/'));
            this.logger.info('[ACTIVE] All ZAP active scanners enabled');
        } catch (error) {
            this.logger.warn(`[ACTIVE] Failed to enable scanners: ${error}`);
        }
    }

    /**
     * Display prominent warning about active scanning
     */
    displayActiveWarning(): void {
        console.log('\n');
        console.log('╔═══════════════════════════════════════════════════════════════════╗');
        console.log('║                    ⚠️  ACTIVE SCANNING WARNING  ⚠️                 ║');
        console.log('╠═══════════════════════════════════════════════════════════════════╣');
        console.log('║  Active scanning will send ATTACK payloads to the target site.   ║');
        console.log('║                                                                   ║');
        console.log('║  • This may trigger WAF/IDS/DDoS protection                       ║');
        console.log('║  • This may cause server load or instability                      ║');
        console.log('║  • This may appear as malicious activity in logs                  ║');
        console.log('║  • This is NOT stealthy                                           ║');
        console.log('║                                                                   ║');
        console.log('║  Only proceed if you have EXPLICIT AUTHORIZATION to scan         ║');
        console.log('║  the target system.                                               ║');
        console.log('╚═══════════════════════════════════════════════════════════════════╝');
        console.log('\n');
    }

    /**
     * Run spider to discover URLs
     */
    async runSpider(targetUrl: string): Promise<SpiderProgress> {
        this.logger.info(`[SPIDER] Starting spider on ${targetUrl}`);

        // Human delay before starting
        await humanDelay(this.SPIDER_DELAY_MS, this.SPIDER_DELAY_MS * 2);

        try {
            // Start spider scan
            const startResponse = await fetch(
                this.buildUrl('/JSON/spider/action/scan/', {
                    url: targetUrl,
                    maxChildren: '50',
                    recurse: 'true',
                    contextName: 'Default Context',
                    subtreeOnly: 'true'
                })
            );

            if (!startResponse.ok) {
                throw new Error(`Spider start failed: ${startResponse.status}`);
            }

            const startData = await startResponse.json() as { scan: string };
            const scanId = startData.scan;
            this.logger.info(`[SPIDER] Started with scan ID: ${scanId}`);

            // Poll for completion
            const startTime = Date.now();
            const progress: SpiderProgress = {
                scanId,
                status: 'running',
                progress: 0,
                urlsFound: 0
            };

            while (Date.now() - startTime < this.SPIDER_TIMEOUT_MS) {
                await sleep(this.POLL_INTERVAL_MS);

                const statusResponse = await fetch(
                    this.buildUrl('/JSON/spider/view/status/', { scanId })
                );

                if (statusResponse.ok) {
                    const statusData = await statusResponse.json() as { status: string };
                    progress.progress = parseInt(statusData.status, 10);

                    // Get URLs found
                    const urlsResponse = await fetch(
                        this.buildUrl('/JSON/spider/view/results/', { scanId })
                    );

                    if (urlsResponse.ok) {
                        const urlsData = await urlsResponse.json() as { results: string[] };
                        progress.urlsFound = urlsData.results?.length || 0;
                    }

                    this.logger.debug(`[SPIDER] Progress: ${progress.progress}% - URLs: ${progress.urlsFound}`);

                    if (progress.progress >= 100) {
                        progress.status = 'completed';
                        break;
                    }
                }
            }

            if (progress.status !== 'completed') {
                this.logger.warn('[SPIDER] Timed out, stopping scan');
                await fetch(this.buildUrl('/JSON/spider/action/stop/', { scanId }));
                progress.status = 'failed';
            }

            this.logger.info(`[SPIDER] Completed - Found ${progress.urlsFound} URLs`);
            return progress;

        } catch (error) {
            this.logger.error(`[SPIDER] Failed: ${error}`);
            return {
                scanId: '',
                status: 'failed',
                progress: 0,
                urlsFound: 0
            };
        }
    }

    /**
     * Run active scan on target
     */
    async runActiveScan(targetUrl: string): Promise<ActiveScanProgress> {
        this.logger.info(`[ACTIVE SCAN] Starting on ${targetUrl}`);

        // Heavy delay before active scanning
        await humanDelay(this.ACTIVE_SCAN_DELAY_MS, this.ACTIVE_SCAN_DELAY_MS * 2);

        try {
            // Start active scan
            const startResponse = await fetch(
                this.buildUrl('/JSON/ascan/action/scan/', {
                    url: targetUrl,
                    recurse: 'true',
                    inScopeOnly: 'true',
                    scanPolicyName: '', // Use default policy
                    method: '',
                    postData: ''
                })
            );

            if (!startResponse.ok) {
                throw new Error(`Active scan start failed: ${startResponse.status}`);
            }

            const startData = await startResponse.json() as { scan: string };
            const scanId = startData.scan;
            this.logger.info(`[ACTIVE SCAN] Started with scan ID: ${scanId}`);

            // Poll for completion
            const startTime = Date.now();
            const progress: ActiveScanProgress = {
                scanId,
                status: 'running',
                progress: 0,
                alertsFound: 0
            };

            while (Date.now() - startTime < this.ACTIVE_SCAN_TIMEOUT_MS) {
                await sleep(this.POLL_INTERVAL_MS * 2); // Slower polling for active scan

                const statusResponse = await fetch(
                    this.buildUrl('/JSON/ascan/view/status/', { scanId })
                );

                if (statusResponse.ok) {
                    const statusData = await statusResponse.json() as { status: string };
                    progress.progress = parseInt(statusData.status, 10);

                    // Get alerts count
                    const alertsResponse = await fetch(
                        this.buildUrl('/JSON/ascan/view/alertsIds/', { scanId })
                    );

                    if (alertsResponse.ok) {
                        const alertsData = await alertsResponse.json() as { alertsIds: string[] };
                        progress.alertsFound = alertsData.alertsIds?.length || 0;
                    }

                    this.logger.info(`[ACTIVE SCAN] Progress: ${progress.progress}% - Alerts: ${progress.alertsFound}`);

                    if (progress.progress >= 100) {
                        progress.status = 'completed';
                        break;
                    }
                }
            }

            if (progress.status !== 'completed') {
                this.logger.warn('[ACTIVE SCAN] Timed out, stopping scan');
                await fetch(this.buildUrl('/JSON/ascan/action/stop/', { scanId }));
                progress.status = 'failed';
            }

            this.logger.info(`[ACTIVE SCAN] Completed - Found ${progress.alertsFound} alerts`);
            return progress;

        } catch (error) {
            this.logger.error(`[ACTIVE SCAN] Failed: ${error}`);
            return {
                scanId: '',
                status: 'failed',
                progress: 0,
                alertsFound: 0
            };
        }
    }

    /**
     * Get all alerts and categorize by source (passive vs active)
     */
    async getAlertsBySource(targetUrl: string): Promise<{ passive: SecurityAlert[]; active: SecurityAlert[] }> {
        try {
            const response = await fetch(
                this.buildUrl('/JSON/alert/view/alerts/', { baseurl: targetUrl })
            );

            if (!response.ok) {
                throw new Error(`Failed to get alerts: ${response.status}`);
            }

            const data = await response.json() as { alerts?: ZapAlertResponse[] };
            const alerts = data.alerts || [];

            const passive: SecurityAlert[] = [];
            const active: SecurityAlert[] = [];

            for (const alert of alerts) {
                const mapped = this.mapAlert(alert);

                // ZAP uses sourceid to indicate scanner source
                // Passive scanner has specific source IDs (typically 3 for passive)
                // Active scanners have different IDs
                const sourceId = parseInt(alert.sourceid || '0', 10);

                // Source ID 3 = passive scanner, others = active scanners
                if (sourceId === 3 || !alert.attack) {
                    passive.push(mapped);
                } else {
                    active.push(mapped);
                }
            }

            return { passive, active };

        } catch (error) {
            this.logger.error(`Failed to get alerts: ${error}`);
            return { passive: [], active: [] };
        }
    }

    /**
     * Map ZAP alert to SecurityAlert format
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
     * Get spider results (discovered URLs)
     */
    async getSpiderResults(scanId: string): Promise<string[]> {
        try {
            const response = await fetch(
                this.buildUrl('/JSON/spider/view/results/', { scanId })
            );

            if (response.ok) {
                const data = await response.json() as { results: string[] };
                return data.results || [];
            }

            return [];
        } catch (error) {
            this.logger.warn(`Failed to get spider results: ${error}`);
            return [];
        }
    }

    /**
     * Run full active scan workflow (spider + active scan)
     */
    async runFullActiveScan(targetUrl: string): Promise<ActiveScanResult> {
        const startTime = Date.now();

        this.displayActiveWarning();

        if (!this.isInitialized) {
            const initialized = await this.initialize();
            if (!initialized) {
                return {
                    spiderUrls: [],
                    passiveAlerts: [],
                    activeAlerts: [],
                    duration: 0,
                    completed: false
                };
            }
        }

        // Phase 1: Spider
        this.logger.info('═══════════════════════════════════════════════════════════');
        this.logger.info('[ACTIVE] Phase 1: Spider Crawl');
        this.logger.info('═══════════════════════════════════════════════════════════');

        const spiderResult = await this.runSpider(targetUrl);
        const spiderUrls = spiderResult.status === 'completed'
            ? await this.getSpiderResults(spiderResult.scanId)
            : [];

        // Delay between phases
        await humanDelay(this.ACTIVE_SCAN_DELAY_MS, this.ACTIVE_SCAN_DELAY_MS * 2);

        // Phase 2: Active Scan
        this.logger.info('═══════════════════════════════════════════════════════════');
        this.logger.info('[ACTIVE] Phase 2: Active Vulnerability Scan');
        this.logger.info('═══════════════════════════════════════════════════════════');

        const activeScanResult = await this.runActiveScan(targetUrl);

        // Phase 3: Collect Results
        this.logger.info('═══════════════════════════════════════════════════════════');
        this.logger.info('[ACTIVE] Phase 3: Collecting Results');
        this.logger.info('═══════════════════════════════════════════════════════════');

        const alerts = await this.getAlertsBySource(targetUrl);

        const duration = Date.now() - startTime;

        this.logger.info(`[ACTIVE] Full scan completed in ${(duration / 1000).toFixed(2)}s`);
        this.logger.info(`[ACTIVE] URLs discovered: ${spiderUrls.length}`);
        this.logger.info(`[ACTIVE] Passive alerts: ${alerts.passive.length}`);
        this.logger.info(`[ACTIVE] Active alerts: ${alerts.active.length}`);

        return {
            spiderUrls,
            passiveAlerts: alerts.passive,
            activeAlerts: alerts.active,
            duration,
            completed: activeScanResult.status === 'completed' || activeScanResult.status === 'failed'
        };
    }

    /**
     * Clean up any running scans
     */
    async cleanup(): Promise<void> {
        try {
            // Stop all spiders
            await fetch(this.buildUrl('/JSON/spider/action/stopAllScans/'));

            // Stop all active scans
            await fetch(this.buildUrl('/JSON/ascan/action/stopAllScans/'));

            this.logger.info('[ACTIVE] Cleanup completed');
        } catch (error) {
            this.logger.warn(`[ACTIVE] Cleanup error: ${error}`);
        }
    }
}

export default ZapActiveScanner;
