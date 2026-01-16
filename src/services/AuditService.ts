/**
 * AuditService
 * 
 * Collects security and performance data using:
 * - Lighthouse for Performance, Accessibility, SEO scores
 * - OWASP ZAP API for passive security alerts (READ-ONLY)
 * 
 * SAFETY: This service NEVER triggers active scans.
 * It only retrieves alerts generated from passive traffic monitoring.
 */

import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import { devices } from 'playwright';
import { getConfig, EnvConfig } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { persistenceService } from './PersistenceService.js';
import { baselineService } from './BaselineService.js';

/**
 * Lighthouse audit scores
 */
export interface LighthouseScores {
    performance: number;
    accessibility: number;
    seo: number;
    bestPractices: number;
}

/**
 * Lighthouse audit details
 */
export interface LighthouseResult {
    scores: LighthouseScores;
    metrics: {
        firstContentfulPaint: number;
        largestContentfulPaint: number;
        totalBlockingTime: number;
        cumulativeLayoutShift: number;
        speedIndex: number;
        timeToInteractive: number;
    };
    audits: {
        passed: number;
        failed: number;
        manual: number;
    };
    url: string;
    fetchTime: string;
}

/**
 * ZAP security alert
 */
export interface SecurityAlert {
    id: string;
    name: string;
    risk: 'High' | 'Medium' | 'Low' | 'Informational';
    confidence: 'High' | 'Medium' | 'Low' | 'User Confirmed';
    description: string;
    url: string;
    solution: string;
    reference: string;
    cweid: string;
    wascid: string;
    count: number;
}

/**
 * ZAP alerts grouped by risk
 */
export interface SecurityAlertsByRisk {
    high: SecurityAlert[];
    medium: SecurityAlert[];
    low: SecurityAlert[];
    informational: SecurityAlert[];
}

/**
 * Combined audit result
 */
export interface AuditResult {
    lighthouse: LighthouseResult | null;
    security_alerts: SecurityAlert[];
    ignored_alerts: SecurityAlert[];
    summary: {
        performanceScore: number;
        accessibilityScore: number;
        seoScore: number;
        highRiskAlerts: number;
        mediumRiskAlerts: number;
        passedAudit: boolean;
    };
    timestamp: string;
    targetUrl: string;
}

/**
 * Lighthouse desktop configuration
 */
const LIGHTHOUSE_DESKTOP_CONFIG = {
    extends: 'lighthouse:default',
    settings: {
        formFactor: 'desktop' as const,
        screenEmulation: {
            mobile: false,
            width: 1920,
            height: 1080,
            deviceScaleFactor: 1,
            disabled: false,
        },
        throttling: {
            rttMs: 40,
            throughputKbps: 10240,
            cpuSlowdownMultiplier: 1,
        },
        emulatedUserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    },
};

/**
 * AuditService Class
 * 
 * Runs performance and security audits on the target site.
 * All security scanning is PASSIVE ONLY - no active attacks.
 */
export class AuditService {
    private readonly config: EnvConfig;
    private chrome: chromeLauncher.LaunchedChrome | null = null;

    /** Minimum passing scores */
    private static readonly THRESHOLDS = {
        performance: 50,
        accessibility: 70,
        seo: 70,
        maxHighAlerts: 0,
        maxMediumAlerts: 3,
    };

    constructor() {
        this.config = getConfig();
    }

    /**
     * Run full audit (Lighthouse + ZAP)
     */
    async runFullAudit(targetUrl?: string, deviceName: string = 'desktop'): Promise<AuditResult> {
        const url = targetUrl || this.config.LIVE_URL;
        logger.info(`Starting full audit on: ${url} (Device: ${deviceName})`);

        // Run Lighthouse audit
        const lighthouseResult = await this.runLighthouseAudit(url, deviceName);

        // Get ZAP security alerts (passive only)
        const securityAlerts = await this.getSecurityAlerts();

        // Filter to High and Medium only AND check baseline
        const allCriticalAlerts = securityAlerts.filter(
            alert => alert.risk === 'High' || alert.risk === 'Medium'
        );

        const criticalAlerts: SecurityAlert[] = [];
        const ignoredAlerts: SecurityAlert[] = [];

        for (const alert of allCriticalAlerts) {
            // Check against baseline (using Plugin ID or Name, no selector, and URL as path)
            if (baselineService.shouldIgnore(alert.id, undefined, alert.url) ||
                baselineService.shouldIgnore(alert.name, undefined, alert.url)) {
                ignoredAlerts.push(alert);
            } else {
                criticalAlerts.push(alert);
            }
        }

        // Calculate summary
        const summary = this.calculateSummary(lighthouseResult, criticalAlerts);

        const result: AuditResult = {
            lighthouse: lighthouseResult,
            security_alerts: criticalAlerts,
            ignored_alerts: ignoredAlerts,
            summary,
            timestamp: new Date().toISOString(),
            targetUrl: url,
        };

        // Log audit result to WAL
        if (persistenceService.isActive()) {
            await persistenceService.log('security_assessment', {
                timestamp: result.timestamp,
                target: result.targetUrl,
                lighthouse: result.lighthouse,
                findings: result.security_alerts,
                summary: result.summary,
                device: deviceName
            });
        }

        this.logAuditSummary(result);

        return result;
    }

    /**
     * Run Lighthouse audit with Desktop configuration
     */
    async runLighthouseAudit(url: string, deviceName: string = 'desktop'): Promise<LighthouseResult | null> {
        logger.info(`Running Lighthouse audit (${deviceName} mode)...`);

        try {
            // Determine Lighthouse Config
            let lighthouseConfig: any = LIGHTHOUSE_DESKTOP_CONFIG;

            if (deviceName !== 'desktop') {
                const device = devices[deviceName];
                if (device) {
                    lighthouseConfig = {
                        extends: 'lighthouse:default',
                        settings: {
                            formFactor: 'mobile',
                            screenEmulation: {
                                mobile: true,
                                width: device.viewport.width,
                                height: device.viewport.height,
                                deviceScaleFactor: device.deviceScaleFactor,
                                disabled: false,
                            },
                            emulatedUserAgent: device.userAgent,
                            // Use default mobile throttling
                        }
                    };
                } else {
                    logger.warn(`Device '${deviceName}' not found, falling back to Desktop config`);
                }
            }

            // Launch Chrome for Lighthouse
            this.chrome = await chromeLauncher.launch({
                chromeFlags: [
                    '--headless',
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage',
                ],
            });

            logger.info(`Chrome launched on port ${this.chrome.port}`);

            // Run Lighthouse audit
            const result = await lighthouse(
                url,
                {
                    port: this.chrome.port,
                    output: 'json',
                    logLevel: 'error',
                    onlyCategories: ['performance', 'accessibility', 'seo', 'best-practices'],
                },
                lighthouseConfig
            );

            if (!result || !result.lhr) {
                throw new Error('Lighthouse returned no results');
            }

            const { lhr } = result;

            // Extract scores (0-100)
            const scores: LighthouseScores = {
                performance: this.extractScore(lhr.categories?.performance?.score),
                accessibility: this.extractScore(lhr.categories?.accessibility?.score),
                seo: this.extractScore(lhr.categories?.seo?.score),
                bestPractices: this.extractScore(lhr.categories?.['best-practices']?.score),
            };

            // Extract performance metrics
            const metrics = {
                firstContentfulPaint: this.extractMetric(lhr.audits, 'first-contentful-paint'),
                largestContentfulPaint: this.extractMetric(lhr.audits, 'largest-contentful-paint'),
                totalBlockingTime: this.extractMetric(lhr.audits, 'total-blocking-time'),
                cumulativeLayoutShift: this.extractMetric(lhr.audits, 'cumulative-layout-shift'),
                speedIndex: this.extractMetric(lhr.audits, 'speed-index'),
                timeToInteractive: this.extractMetric(lhr.audits, 'interactive'),
            };

            // Count audits
            const audits = this.countAudits(lhr.audits);

            logger.info('Lighthouse audit completed', scores);

            return {
                scores,
                metrics,
                audits,
                url: lhr.requestedUrl || url,
                fetchTime: lhr.fetchTime || new Date().toISOString(),
            };

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.error(`Lighthouse audit failed: ${errMsg}`);
            return null;
        } finally {
            await this.closeLighthouseChrome();
        }
    }

    /**
     * Check if ZAP proxy is available
     * @returns true if ZAP is reachable, false otherwise
     */
    async isZapAvailable(): Promise<boolean> {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);

            const response = await fetch(
                `${this.config.ZAP_PROXY_URL}/JSON/core/view/version/`,
                { signal: controller.signal }
            );
            clearTimeout(timeoutId);

            return response.ok;
        } catch {
            return false;
        }
    }

    /**
     * Get security alerts from ZAP API (PASSIVE ONLY)
     *
     * IMPORTANT: This only retrieves alerts from passive traffic monitoring.
     * It does NOT trigger any active scanning.
     */
    async getSecurityAlerts(): Promise<SecurityAlert[]> {
        logger.info('Fetching ZAP passive security alerts...');
        logger.info('NOTE: Passive scanning only - no active attacks triggered');

        // Pre-check if ZAP is available
        const zapAvailable = await this.isZapAvailable();
        if (!zapAvailable) {
            logger.warn('ZAP proxy is not running or not reachable');
            logger.warn('Continuing without ZAP security data');
            return [];
        }

        try {
            // Query ZAP API for alerts by risk
            const response = await fetch(
                `${this.config.ZAP_PROXY_URL}/JSON/alert/view/alertsByRisk/`
            );

            if (!response.ok) {
                throw new Error(`ZAP API returned status ${response.status}`);
            }

            const data = await response.json() as { alertsByRisk?: AlertsByRiskResponse[] };

            const alerts: SecurityAlert[] = [];

            // Parse alerts from response
            if (data.alertsByRisk && Array.isArray(data.alertsByRisk)) {
                for (const riskGroup of data.alertsByRisk) {
                    const risk = this.mapRiskLevel(riskGroup.risk || '');

                    if (riskGroup.alerts && Array.isArray(riskGroup.alerts)) {
                        for (const alert of riskGroup.alerts) {
                            alerts.push({
                                id: alert.id || '',
                                name: alert.name || alert.alert || 'Unknown',
                                risk,
                                confidence: this.mapConfidence(alert.confidence || ''),
                                description: alert.description || '',
                                url: alert.url || '',
                                solution: alert.solution || '',
                                reference: alert.reference || '',
                                cweid: alert.cweid || '',
                                wascid: alert.wascid || '',
                                count: parseInt(alert.count || '1', 10),
                            });
                        }
                    }
                }
            }

            // Log summary
            const highCount = alerts.filter(a => a.risk === 'High').length;
            const mediumCount = alerts.filter(a => a.risk === 'Medium').length;

            logger.info(`Found ${alerts.length} total alerts`);
            logger.info(`High risk: ${highCount}, Medium risk: ${mediumCount}`);

            return alerts;

        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            logger.warn(`Failed to fetch ZAP alerts: ${errMsg}`);
            logger.warn('Continuing without ZAP security data');
            return [];
        }
    }

    /**
     * Get only High and Medium risk alerts
     */
    async getCriticalAlerts(): Promise<SecurityAlert[]> {
        const allAlerts = await this.getSecurityAlerts();
        return allAlerts.filter(
            alert => alert.risk === 'High' || alert.risk === 'Medium'
        );
    }

    /**
     * Calculate summary from results
     */
    private calculateSummary(
        lighthouse: LighthouseResult | null,
        criticalAlerts: SecurityAlert[]
    ): AuditResult['summary'] {
        const highRiskAlerts = criticalAlerts.filter(a => a.risk === 'High').length;
        const mediumRiskAlerts = criticalAlerts.filter(a => a.risk === 'Medium').length;

        const performanceScore = lighthouse?.scores.performance ?? 0;
        const accessibilityScore = lighthouse?.scores.accessibility ?? 0;
        const seoScore = lighthouse?.scores.seo ?? 0;

        // Determine if audit passed
        const passedAudit =
            performanceScore >= AuditService.THRESHOLDS.performance &&
            accessibilityScore >= AuditService.THRESHOLDS.accessibility &&
            seoScore >= AuditService.THRESHOLDS.seo &&
            highRiskAlerts <= AuditService.THRESHOLDS.maxHighAlerts &&
            mediumRiskAlerts <= AuditService.THRESHOLDS.maxMediumAlerts;

        return {
            performanceScore,
            accessibilityScore,
            seoScore,
            highRiskAlerts,
            mediumRiskAlerts,
            passedAudit,
        };
    }

    /**
     * Log audit summary
     */
    private logAuditSummary(result: AuditResult): void {
        logger.info('═'.repeat(50));
        logger.info('AUDIT SUMMARY');
        logger.info('═'.repeat(50));
        logger.info(`Target: ${result.targetUrl}`);
        logger.info('');

        if (result.lighthouse) {
            logger.info('Lighthouse Scores:');
            logger.info(`  Performance:    ${result.lighthouse.scores.performance}/100`);
            logger.info(`  Accessibility:  ${result.lighthouse.scores.accessibility}/100`);
            logger.info(`  SEO:            ${result.lighthouse.scores.seo}/100`);
            logger.info(`  Best Practices: ${result.lighthouse.scores.bestPractices}/100`);
        }

        logger.info('');
        logger.info('Security Alerts:');
        logger.info(`  High Risk:   ${result.summary.highRiskAlerts}`);
        logger.info(`  Medium Risk: ${result.summary.mediumRiskAlerts}`);
        logger.info('');

        if (result.summary.passedAudit) {
            logger.info('✓ AUDIT PASSED');
        } else {
            logger.error('✗ AUDIT FAILED');
        }

        logger.info('═'.repeat(50));
    }

    /**
     * Extract score from Lighthouse category (0-1 to 0-100)
     */
    private extractScore(score: number | null | undefined): number {
        if (score === null || score === undefined) return 0;
        return Math.round(score * 100);
    }

    /**
     * Extract numeric metric value from audits
     */
    private extractMetric(audits: LighthouseAudits | undefined, auditId: string): number {
        const audit = audits?.[auditId];
        if (!audit) return 0;
        return Math.round(audit.numericValue || 0);
    }

    /**
     * Count passed/failed/manual audits
     */
    private countAudits(audits: LighthouseAudits | undefined): { passed: number; failed: number; manual: number } {
        let passed = 0;
        let failed = 0;
        let manual = 0;

        if (audits) {
            for (const audit of Object.values(audits)) {
                if (audit.scoreDisplayMode === 'manual') {
                    manual++;
                } else if (audit.score === 1) {
                    passed++;
                } else if (audit.score === 0) {
                    failed++;
                }
            }
        }

        return { passed, failed, manual };
    }

    /**
     * Map ZAP risk string to typed risk level
     */
    private mapRiskLevel(risk: string): SecurityAlert['risk'] {
        switch (risk?.toLowerCase()) {
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
     * Map ZAP confidence string to typed confidence level
     */
    private mapConfidence(confidence: string): SecurityAlert['confidence'] {
        switch (confidence?.toLowerCase()) {
            case 'high':
                return 'High';
            case 'medium':
                return 'Medium';
            case 'low':
                return 'Low';
            case 'user confirmed':
                return 'User Confirmed';
            default:
                return 'Medium';
        }
    }

    /**
     * Close Lighthouse Chrome instance
     */
    private async closeLighthouseChrome(): Promise<void> {
        if (this.chrome) {
            try {
                await this.chrome.kill();
            } catch (e) {
                // Chrome cleanup errors are typically benign (already closed, process not found)
                logger.debug(`Chrome cleanup: ${e instanceof Error ? e.message : String(e)}`);
            }
            this.chrome = null;
        }
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        await this.closeLighthouseChrome();
    }
}

/**
 * ZAP API response types
 */
interface AlertsByRiskResponse {
    risk: string;
    alerts: ZapAlertResponse[];
}

interface ZapAlertResponse {
    id?: string;
    name?: string;
    alert?: string;
    risk?: string;
    confidence?: string;
    description?: string;
    url?: string;
    solution?: string;
    reference?: string;
    cweid?: string;
    wascid?: string;
    count?: string;
}

/**
 * Lighthouse audit item structure
 */
interface LighthouseAudit {
    id?: string;
    title?: string;
    score?: number | null;
    scoreDisplayMode?: string;
    numericValue?: number;
    displayValue?: string;
}

/**
 * Lighthouse audits collection
 */
interface LighthouseAudits {
    [auditId: string]: LighthouseAudit;
}

export default AuditService;
