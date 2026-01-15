/**
 * Live-Site Compliance Monitor (LSCM)
 * Main Entry Point
 * 
 * Orchestrates the complete compliance monitoring flow:
 * 1. Initialize browser with ZAP proxy
 * 2. Authenticate to the target site
 * 3. Run performance and security audits
 * 4. Generate and save report
 * 
 * SAFETY FEATURES:
 * - All traffic proxied through ZAP (passive mode only)
 * - Human-like delays between all actions
 * - Browser cleanup in finally block (no zombie processes)
 * - Read-only operations only
 */
import * as fs from 'fs';
import * as path from 'path';
import { logger, logSection, logSuccess, logFailure } from './utils/logger';
import { createConfig } from './config/compliance.config';
import { ComplianceRunner } from './services/ComplianceRunner';
import { FleetReportGenerator, FleetSiteResult } from './services/FleetReportGenerator';
import { WebhookService } from './services/WebhookService';

/**
 * Main execution function
 */
async function main(): Promise<void> {
    // Parse command line arguments
    const args = process.argv.slice(2);
    const profileArg = args.find(arg => arg.startsWith('--profile='));
    const profileName = profileArg ? profileArg.split('=')[1] : 'standard';

    // Load merged configuration
    const config = createConfig(profileName);
    logger.info(`Loaded Profile: ${config.name}`);

    // Determine Targets
    // Determine Targets
    let targets: string[] = [];
    if (Array.isArray(config.targetUrl)) {
        targets = config.targetUrl;
    } else if (config.targetUrl.endsWith('.json')) {
        try {
            const targetsPath = path.resolve(config.targetUrl);
            logger.info(`Loading targets from: ${targetsPath}`);

            if (fs.existsSync(targetsPath)) {
                const fileContent = fs.readFileSync(targetsPath, 'utf-8');
                const jsonData = JSON.parse(fileContent);

                if (Array.isArray(jsonData)) {
                    targets = jsonData;
                } else if (jsonData.targets && Array.isArray(jsonData.targets)) {
                    targets = jsonData.targets;
                } else {
                    throw new Error('Invalid JSON format. Expected array or object with "targets" array.');
                }
                logger.info(`Loaded ${targets.length} targets from file.`);
            } else {
                throw new Error(`File not found: ${targetsPath}`);
            }
        } catch (error) {
            logger.error(`Failed to load targets file: ${error instanceof Error ? error.message : String(error)}`);
            process.exit(1);
        }
    } else {
        targets = [config.targetUrl];
    }

    logger.info(`Fleet Mode: ${targets.length > 1 ? 'Enabled' : 'Disabled'}`);
    logger.info(`Targets: ${targets.length} sites to scan`);

    const runner = new ComplianceRunner(config);
    const fleetResults: FleetSiteResult[] = [];

    const startTime = Date.now();

    try {
        logSection('Live Site Compliance Monitor - Fleet Execution');

        // Loop through all targets
        for (let i = 0; i < targets.length; i++) {
            const target = targets[i];
            logger.info('');
            logger.info(`>>> Processing Target ${i + 1}/${targets.length}: ${target} <<<`);

            const result = await runner.run(target);
            fleetResults.push(result);
        }

        // Generate Fleet Report
        if (targets.length > 0) {
            const fleetReportGenerator = new FleetReportGenerator(config.REPORTS_DIR);
            const fleetDashboardPath = await fleetReportGenerator.generate(fleetResults);

            logger.info('');
            logSection('Fleet Execution Complete');
            logSuccess(`Fleet Dashboard: ${fleetDashboardPath}`);

            // Print Fleet Summary to Console
            console.table(fleetResults.map(r => ({
                Domain: r.domain,
                Score: r.healthScore,
                Status: r.status,
                Criticals: r.criticalIssues
            })));

            // Send Webhook Alerts
            if (config.webhook && config.webhook.url) {
                logSection('Sending Webhook Alerts');
                for (const result of fleetResults) {
                    const summaryMock = {
                        healthScore: result.healthScore,
                        securityCritical: result.criticalIssues,
                        securityHigh: 0,
                        highRiskAlerts: 0,
                        mediumRiskAlerts: 0,
                        performanceScore: 0,
                        accessibilityScore: 0,
                        seoScore: 0,
                        vulnerableLibraries: []
                    };
                    await WebhookService.sendAlert(summaryMock, result.url, result.reportPath);
                }
            }
        }

        const totalDuration = Date.now() - startTime;
        logger.info(`Total Fleet Duration: ${(totalDuration / 1000).toFixed(2)}s`);

        // Exit Code Logic
        const anyFailures = fleetResults.some(r => r.status === 'fail');
        process.exitCode = anyFailures ? 1 : 0;

    } catch (error) {
        logFailure(`Fatal Fleet Error: ${error}`);
        process.exitCode = 2;
    }
}

// ═══════════════════════════════════════════════════════════
// PROCESS HANDLERS & GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════════

import { persistenceService, PersistenceService } from './services/PersistenceService';
import { HtmlReportGenerator } from './services/HtmlReportGenerator';
import { BrowserService } from './services/BrowserService';

/**
 * Graceful Shutdown Handler
 * Generates a partial report from the WAL before exiting
 */
async function shutdown(signal: string): Promise<void> {
    logger.info('');
    logSection(`🛑 Received ${signal}. Generating partial report...`);

    const currentLog = persistenceService.getLogFilePath();

    if (currentLog && fs.existsSync(currentLog)) {
        try {
            logger.info('Hydrating partial session data...');
            const session = PersistenceService.hydrate(currentLog);

            // Reconstruct a partial report object
            const partialReport: any = {
                meta: {
                    version: '1.0.0-partial',
                    generatedAt: new Date().toISOString(),
                    targetUrl: session.metadata?.startUrl || 'unknown',
                    duration: 0,
                    isPartial: true
                },
                authentication: { success: false, duration: 0 },
                crawl: {
                    pagesVisited: session.pageResults.length,
                    failedPages: 0,
                    suspiciousPages: 0,
                    pageResults: session.pageResults
                },
                integrity: {
                    testsRun: session.entryCount,
                    passed: 0,
                    failed: 0,
                    results: []
                },
                network_incidents: session.networkIncidents,
                leaked_secrets: session.leakedSecrets,
                supabase_issues: session.supabaseIssues,
                vulnerable_libraries: session.vulnLibraries,
                security_assessment: { findings: session.securityAssessments, summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, totalTests: 0 } },
                lighthouse: { scores: { performance: 0, accessibility: 0, seo: 0, bestPractices: 0 } },
                security_alerts: session.securityFindings,
                summary: {
                    performanceScore: 0,
                    accessibilityScore: 0,
                    seoScore: 0,
                    highRiskAlerts: 0,
                    mediumRiskAlerts: 0,
                    passedAudit: false
                }
            };

            const config = createConfig();
            const htmlReportGenerator = new HtmlReportGenerator(config.REPORTS_DIR);
            const reportPath = await htmlReportGenerator.generate(partialReport);

            logSuccess(`Partial report generated: ${reportPath}`);
        } catch (error) {
            logger.error(`Failed to generate partial report: ${error}`);
        }
    } else {
        logger.info('No active WAL session found to hydrate.');
    }

    try {
        logger.info('Cleaning up active browser processes...');
        await BrowserService.closeAll();
    } catch (e) { }

    logger.info('Shutdown complete.');
    process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
    logger.error(`Unhandled Rejection: ${reason}`);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    logger.error(`Uncaught Exception: ${error.message}`);
    process.exit(1);
});

main();
