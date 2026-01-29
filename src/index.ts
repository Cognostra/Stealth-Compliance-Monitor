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
import * as fs from 'node:fs';
import pLimit from 'p-limit'; // Concurrency control
import { logger, logSection, logSuccess, logFailure } from './utils/logger.js';
import { createConfig, ComplianceConfig } from './config/compliance.config.js';
import { ComplianceRunner } from './services/ComplianceRunner.js';
import { FleetReportGenerator, FleetSiteResult } from './services/FleetReportGenerator.js';
import { WebhookService } from './services/WebhookService.js';
import { initDeterministic } from './utils/random.js';
import { ProgressReporter } from './utils/progress.js';

// v3 imports
import { parseV3Flags, V3_VERSION, V3IntegrationService, parseGeneratePolicyArgs, generatePolicy, V3FeatureFlags } from './v3/index.js';
import { CronScheduler } from './v3/scheduler/CronScheduler.js';
import { TrendService } from './v3/services/TrendService.js';
import { parseCliOptions, loadTargets, CliOptions } from './config/cli.js';

/**
 * Display help message
 */
function displayHelp(): void {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║           Stealth Compliance Monitor - Help                       ║
╚═══════════════════════════════════════════════════════════════════╝

Usage: npx ts-node src/index.ts [options]

Options:
  --profile=<name>   Select scan profile (default: standard)
                     Profiles: smoke, standard, deep, deep-active

  --active           Enable ZAP active scanning (spider + attack payloads)
                     ⚠️  WARNING: This is AGGRESSIVE and NOT stealthy
                     Only use with explicit authorization!
                     Requires ACTIVE_SCAN_ALLOWED=true and allowlist

  --headed           Run browser in visible (headed) mode for debugging
  --slow-mo=<ms>     Slow down browser actions by specified milliseconds
  --debug            Enable full debug mode (headed + devtools + pause on failure)

  --sarif[=path]     Output SARIF 2.1 format (for GitHub Code Scanning)
                     Without path: prints to stdout
                     With path: writes to specified file

  --policy=<path>    Load policy-as-code rules from YAML file
                     Policies can fail/warn builds based on findings

  --executive-report Generate a PDF Executive Summary
                     Output: reports/executive-summary-<timestamp>.pdf

  --compliance=<fw>  Include compliance framework mapping in report
                     Frameworks: soc2, gdpr, hipaa (comma-separated)

  --generate-policy=<profile>  Generate a policy template file
                     Profiles: strict, standard, minimal
                     Output: .compliance-policy.yml

  --init             Run interactive initialization wizard

  --help, -h         Show this help message

  --ai-fix[=model]   Generate local LLM remediation via Ollama
                     Without model: uses OLLAMA_MODEL (default: codellama:13b)
                     With model: e.g. --ai-fix=deepseek-coder:6.7b

  --flutter-semantics  Enable Flutter web accessibility semantics checking

  --target-type=electron  Audit an Electron app instead of a URL
  --electron-path=<path>  Path to Electron executable
  --electron-args=<args>  Extra args for the Electron process

Profiles:
  smoke        Quick health check (1 page, no security tests)
  standard     Regular CI/CD scans (15 pages, passive only)
  deep         Full assessment (50 pages, black-box probes)
  deep-active  Full active scan (50 pages, ZAP spider + active)
  fintech      Financial/crypto compliance (30 pages, PCI-DSS + crypto checks)

v3 Features (${V3_VERSION}):
  SARIF output enables GitHub Code Scanning integration
  Policy-as-code enables custom pass/fail rules
  Compliance mapping enables SOC2/GDPR/HIPAA audit evidence

Examples:
  npm start                           # Standard profile
  npm start -- --profile=smoke        # Quick smoke test
  npm start -- --profile=deep         # Deep passive scan
  npm start -- --profile=fintech      # Fintech compliance scan
  npm start -- --active               # Active scanning (be careful!)
  npm start -- --sarif=results.sarif  # Output SARIF for GitHub
  npm start -- --compliance=soc2,gdpr # Include compliance mapping
  npm start -- --policy=.compliance-policy.yml  # Custom policy rules
  npm start -- --ai-fix               # Generate local LLM remediations
  npm start -- --target-type=electron --electron-path=/path/to/app  # Electron audit

Environment Variables:
  See .env.example for full configuration options.
    Active scan guardrails: ACTIVE_SCAN_ALLOWED, ACTIVE_SCAN_ALLOWLIST
    Deterministic mode: DETERMINISTIC_MODE, DETERMINISTIC_SEED
    Redaction: REDACTION_ENABLED
`);
}

/**
 * Main execution function
 */
async function main(): Promise<void> {

    // Parse command line arguments
    const args = process.argv.slice(2);

    // Check for --help flag
    if (args.includes('--help') || args.includes('-h')) {
        displayHelp();
        process.exit(0);
    }

    // Check for --init wizard
    if (args.includes('--init')) {
        const { runInitWizard } = await import('./v3/commands/index.js');
        await runInitWizard();
        process.exit(0);
    }

    // Check for --generate-policy command (standalone action)
    const generatePolicyOptions = parseGeneratePolicyArgs(args);
    if (generatePolicyOptions) {
        const result = generatePolicy(generatePolicyOptions);
        if (result.success) {
            console.log(`✅ ${result.message}`);
            process.exit(0);
        } else {
            console.error(`❌ ${result.message}`);
            process.exit(1);
        }
    }

    // Parse options
    const cliOptions = parseCliOptions(args);

    // Parse v3 feature flags
    const v3Flags = parseV3Flags(args);
    const v3Service = new V3IntegrationService();

    // Load merged configuration
    let config: ComplianceConfig;
    try {
        config = createConfig(cliOptions.profileName);
    } catch (error) {
        console.error('Failed to load configuration:', error);
        process.exit(1);
    }

    // Override target if provided as positional argument
    if (cliOptions.positionalTarget) {
        config.targetUrl = cliOptions.positionalTarget;
        config.LIVE_URL = cliOptions.positionalTarget;
        logger.info(`Target override from CLI: ${cliOptions.positionalTarget}`);
    }

    // Deterministic mode for stable CI runs
    if (config.deterministicMode) {
        initDeterministic(config.deterministicSeed);
        logger.info(`Deterministic mode enabled (seed=${config.deterministicSeed})`);
    }

    // Active scan override
    if (cliOptions.activeFlag) {
        (config as { activeScanning: boolean }).activeScanning = true;
    }

    // Guardrails
    applySecurityGuardrails(config);

    // Apply debug mode overrides from CLI flags
    applyDebugOverrides(config, cliOptions);

    logger.info(`Loaded Profile: ${config.name}`);
    logger.info(`Active Scanning: ${config.activeScanning ? 'ENABLED ⚠️' : 'Disabled'}`);

    // Determine Targets
    const targets = loadTargets(config.targetUrl);

    logger.info(`Fleet Mode: ${targets.length > 1 ? 'Enabled' : 'Disabled'}`);
    logger.info(`Targets: ${targets.length} sites to scan`);


    // Check for Cron Schedule
    if (config.CRON_SCHEDULE) {
        const scheduler = new CronScheduler(logger);
        scheduler.start(config.CRON_SCHEDULE, async () => {
             const exitCode = await executeAudit(config, targets, v3Flags, v3Service, cliOptions.profileName, Number.parseInt(process.env.FLEET_CONCURRENCY || '5', 10));
             logger.info(`Scheduled scan finished with exit code: ${exitCode}`);
        });
        
        // Keep process alive
        logger.info('Daemon mode enabled. Waiting for scheduled runs...');
        // Should not exit main()
    } else {
        // Run once
        const CONCURRENCY = Number.parseInt(process.env.FLEET_CONCURRENCY || '5', 10);
        const exitCode = await executeAudit(config, targets, v3Flags, v3Service, cliOptions.profileName, CONCURRENCY);
        process.exitCode = exitCode;
    }
}

function applySecurityGuardrails(config: ComplianceConfig) {
    const allowlist = config.activeScanAllowlist || [];
    if (config.activeScanning) {
        if (!config.activeScanAllowed) {
            logger.warn('Active scanning requested but ACTIVE_SCAN_ALLOWED=false. Disabling active scan.');
            config.activeScanning = false;
        } else if (allowlist.length > 0) {
            const allowed = allowlist.some((allowedTarget: string) => {
                return config.LIVE_URL.includes(allowedTarget) || allowedTarget === config.LIVE_URL;
            });
            if (!allowed) {
                logger.warn('Active scanning requested but target not in ACTIVE_SCAN_ALLOWLIST. Disabling active scan.');
                config.activeScanning = false;
            }
        }
    }
}

function applyDebugOverrides(config: ComplianceConfig, cliOptions: CliOptions) {
    if (cliOptions.headedFlag || cliOptions.debugFlag) {
        config.DEBUG_HEADED = true;
        logger.info('🔍 Debug: Headed mode enabled');
    }
    if (cliOptions.debugFlag) {
        config.DEBUG_DEVTOOLS = true;
        config.DEBUG_PAUSE_ON_FAILURE = true;
        config.DEBUG_CAPTURE_CONSOLE = true;
        logger.info('🔍 Debug: Full debug mode enabled (devtools + pause on failure)');
    }
    if (cliOptions.slowMoValue > 0) {
        config.DEBUG_SLOW_MO = cliOptions.slowMoValue;
        logger.info(`🔍 Debug: SlowMo set to ${cliOptions.slowMoValue}ms`);
    }
}

/**
 * Execute a full audit cycle
 */
async function executeAudit(
    config: ComplianceConfig, 
    targets: string[], 
    v3Flags: V3FeatureFlags, 
    v3Service: V3IntegrationService, 
    profileName: string,
    concurrency: number
): Promise<number> {
    const fleetResults: FleetSiteResult[] = [];
    const startTime = Date.now();
    const limit = pLimit(concurrency);
    const trendService = new TrendService(logger);

    try {
        logSection(`Live Site Compliance Monitor - Fleet Execution (Concurrency: ${concurrency})`);

        // Create promises for all targets with concurrency limit
        const scanPromises = targets.map((target, index) => limit(async () => {
            // Instantiate runner per-target to ensure isolation
            const runner = new ComplianceRunner(config);
            
            logger.info('');
            logger.info(`>>> Starting Target ${index + 1}/${targets.length}: ${target} <<<`);

            const progress = new ProgressReporter(`Target ${index + 1}/${targets.length}`);
            try {
                    if (!URL.canParse(target)) {
               logger.error(`Skipping invalid target URL: ${target}`);
               return; 
            }
            const result = await runner.run(target, progress);
                
                // Record trend data
                trendService.addRecord({
                    timestamp: new Date().toISOString(),
                    runId: startTime.toString(),
                    targetUrl: target,
                    overallScore: result.healthScore,
                    performanceScore: result.scores?.performance || 0,
                    securityCritical: result.criticalIssues
                });
                
                return result;
            } catch (error) {
                logger.error(`Failed to scan target ${target}: ${error}`);
                // Return failed result structure
                return {
                    url: target,
                    domain: new URL(target).hostname,
                    healthScore: 0,
                    reportPath: '#',
                    criticalIssues: 0,
                    status: 'fail' as const
                };
            }
        }));

        // Wait for all scans to complete
        // Wait for all scans to complete
        const results = (await Promise.all(scanPromises)).filter((r): r is FleetSiteResult => r !== undefined);
        fleetResults.push(...results);

        // Generate Fleet Report
        if (targets.length > 0) {
            const fleetReportGenerator = new FleetReportGenerator(config.REPORTS_DIR);
            const fleetDashboardPath = await fleetReportGenerator.generate(fleetResults, trendService.getAllHistory());

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
            if (config.webhook?.url) {
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
                        vulnerableLibraries: 0
                    };
                    await WebhookService.sendAlert(summaryMock, result.url, result.reportPath);
                }
            }
        }

        const totalDuration = Date.now() - startTime;
        logger.info(`Total Fleet Duration: ${(totalDuration / 1000).toFixed(2)}s`);

        // Exit Code Logic
        const anyFailures = fleetResults.some(r => r.status === 'fail');
        let exitCode = anyFailures ? 1 : 0;

        // ══════════════════════════════════════════════════════════════
        // V3 Feature Processing
        // ══════════════════════════════════════════════════════════════
        if (v3Flags.sarif || v3Flags.policy || v3Flags.compliance || v3Flags.executiveReport) {
            logSection('v3 Feature Processing');

            // Use extracted processor
            const { processV3Features } = await import('./v3/processor.js');
            exitCode = await processV3Features({
                config,
                targets,
                v3Flags,
                v3Service,
                profileName,
                totalDuration,
                currentExitCode: exitCode,
                anyFailures,
                trendService
            });
        }

        // ══════════════════════════════════════════════════════════════
        // Local LLM Remediation (--ai-fix via Ollama)
        // ══════════════════════════════════════════════════════════════
        const cliOptions = parseCliOptions(process.argv.slice(2));
        if (cliOptions.aiFixFlag) {
            logSection('Local LLM Remediation (Ollama)');
            try {
                const { OllamaService } = await import('./services/OllamaService.js');
                const ollama = new OllamaService({
                    baseUrl: config.OLLAMA_URL,
                    model: cliOptions.aiFixModel || config.OLLAMA_MODEL,
                });

                const available = await ollama.isAvailable();
                if (!available) {
                    logger.error(`Ollama not available at ${ollama.getBaseUrl()}. Ensure Ollama is running.`);
                } else {
                    // Read latest fleet summary for findings
                    const summaryPath = `${config.REPORTS_DIR}/fleet-summary.json`;
                    if (fs.existsSync(summaryPath)) {
                        const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf-8'));
                        const findings = (summary.results || [])
                            .filter((r: { criticalIssues?: number; status?: string }) => (r.criticalIssues || 0) > 0 || r.status === 'fail')
                            .slice(0, 5)
                            .map((r: { url?: string; criticalIssues?: number; status?: string }) => ({
                                findingType: 'compliance-failure',
                                severity: (r.criticalIssues || 0) > 0 ? 'critical' : 'high',
                                description: `Compliance failure for ${r.url || 'unknown'}`,
                                url: r.url,
                            }));

                        if (findings.length > 0) {
                            logger.info(`Generating remediations for ${findings.length} findings using ${ollama.getModel()}`);
                            const results = await ollama.generateRemediations(findings, {
                                onProgress: (current, total) => logger.info(`Remediation ${current}/${total}...`),
                            });
                            for (const result of results) {
                                logger.info(`\n--- Remediation for: ${result.finding.findingType} ---`);
                                console.log(result.remediation);
                            }
                        } else {
                            logger.info('No critical findings to remediate.');
                        }
                    } else {
                        logger.warn('No fleet summary found for AI remediation.');
                    }
                }
            } catch (error) {
                logger.error(`AI fix failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }

        return exitCode;

    } catch (error) {
        logFailure(`Fatal Fleet Error: ${error}`);
        return 2;
    }
}

// ═══════════════════════════════════════════════════════════
// PROCESS HANDLERS & GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════════

import { persistenceService, PersistenceService } from './services/PersistenceService.js';
import { HtmlReportGenerator } from './services/HtmlReportGenerator.js';
import { BrowserService } from './services/BrowserService.js';

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
            const session = PersistenceService.hydrate(currentLog, {
                include: [
                    'metadata',
                    'pageResults',
                    'networkIncidents',
                    'leakedSecrets',
                    'consoleErrors',
                    'supabaseIssues',
                    'vulnLibraries',
                    'securityAssessments',
                    'entryCount',
                    'isComplete',
                ],
            });

            type ReportPayload = Parameters<HtmlReportGenerator['generate']>[0];
            const partialSecurityFindings = session.securityAssessments as unknown as NonNullable<ReportPayload['security_assessment']>['findings'];

            // Reconstruct a partial report object
            const partialReport: ReportPayload = {
                meta: {
                    version: '1.0.0-partial',
                    generatedAt: new Date().toISOString(),
                    targetUrl: session.metadata?.startUrl || 'unknown',
                    duration: 0
                },
                authentication: { success: false, duration: 0 },
                crawl: {
                    pagesVisited: session.pageResults.length,
                    failedPages: 0,
                    suspiciousPages: 0,
                    totalConsoleErrors: session.consoleErrors.length,
                    pageResults: session.pageResults as unknown as ReportPayload['crawl']['pageResults']
                },
                integrity: {
                    testsRun: session.entryCount,
                    passed: 0,
                    failed: 0,
                    results: []
                },
                network_incidents: session.networkIncidents as ReportPayload['network_incidents'],
                leaked_secrets: session.leakedSecrets as ReportPayload['leaked_secrets'],
                supabase_issues: session.supabaseIssues as ReportPayload['supabase_issues'],
                vulnerable_libraries: session.vulnLibraries as ReportPayload['vulnerable_libraries'],
                security_assessment: partialSecurityFindings.length > 0 ? {
                    target: session.metadata?.startUrl || 'unknown',
                    timestamp: session.metadata?.startTime || new Date().toISOString(),
                    duration: 0,
                    findings: partialSecurityFindings,
                    summary: {
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 0,
                        info: 0,
                        totalTests: partialSecurityFindings.length
                    },
                    reconnaissance: {
                        endpoints: [],
                        authMechanism: 'unknown',
                        techStack: [],
                        cookies: []
                    }
                } : null,
                lighthouse: {
                    scores: { performance: 0, accessibility: 0, seo: 0, bestPractices: 0 },
                    metrics: {
                        firstContentfulPaint: 0,
                        largestContentfulPaint: 0,
                        totalBlockingTime: 0,
                        cumulativeLayoutShift: 0,
                        speedIndex: 0,
                        timeToInteractive: 0
                    }
                },
                security_alerts: [],
                summary: {
                    performanceScore: 0,
                    accessibilityScore: 0,
                    seoScore: 0,
                    highRiskAlerts: 0,
                    mediumRiskAlerts: 0,
                    passedAudit: false,
                    crawlPagesInvalid: 0,
                    crawlPagesSuspicious: 0,
                    integrityFailures: 0
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
    } catch { }

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

await main();
