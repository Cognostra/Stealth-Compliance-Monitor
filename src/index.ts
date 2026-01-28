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
import { logger, logSection, logSuccess, logFailure } from './utils/logger.js';
import { createConfig } from './config/compliance.config.js';
import { ComplianceRunner } from './services/ComplianceRunner.js';
import { FleetReportGenerator, FleetSiteResult } from './services/FleetReportGenerator.js';
import { WebhookService } from './services/WebhookService.js';
import { initDeterministic } from './utils/random.js';
import { ProgressReporter } from './utils/progress.js';

// v3 imports
import { parseV3Flags, V3_VERSION, V3IntegrationService, parseGeneratePolicyArgs, generatePolicy } from './v3/index.js';

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

  --compliance=<fw>  Include compliance framework mapping in report
                     Frameworks: soc2, gdpr, hipaa (comma-separated)

  --generate-policy=<profile>  Generate a policy template file
                     Profiles: strict, standard, minimal
                     Output: .compliance-policy.yml

  --help, -h         Show this help message

Profiles:
  smoke        Quick health check (1 page, no security tests)
  standard     Regular CI/CD scans (15 pages, passive only)
  deep         Full assessment (50 pages, black-box probes)
  deep-active  Full active scan (50 pages, ZAP spider + active)

v3 Features (${V3_VERSION}):
  SARIF output enables GitHub Code Scanning integration
  Policy-as-code enables custom pass/fail rules
  Compliance mapping enables SOC2/GDPR/HIPAA audit evidence

Examples:
  npm start                           # Standard profile
  npm start -- --profile=smoke        # Quick smoke test
  npm start -- --profile=deep         # Deep passive scan
  npm start -- --active               # Active scanning (be careful!)
  npm start -- --sarif=results.sarif  # Output SARIF for GitHub
  npm start -- --compliance=soc2,gdpr # Include compliance mapping
  npm start -- --policy=.compliance-policy.yml  # Custom policy rules

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

    const profileArg = args.find(arg => arg.startsWith('--profile='));
    const activeFlag = args.includes('--active');
    let profileName = profileArg ? profileArg.split('=')[1] : 'standard';

    // Parse debug flags
    const headedFlag = args.includes('--headed');
    const debugFlag = args.includes('--debug');
    const slowMoArg = args.find(arg => arg.startsWith('--slow-mo='));
    const slowMoValue = slowMoArg ? parseInt(slowMoArg.split('=')[1], 10) : 0;

    // Parse v3 feature flags
    const v3Flags = parseV3Flags(args);
    const v3Service = new V3IntegrationService();

    // If --active flag is set, force deep-active profile
    if (activeFlag && !profileArg) {
        profileName = 'deep-active';
        logger.warn('⚠️  --active flag detected, using deep-active profile');
    }

    // Load merged configuration
    const config = createConfig(profileName);

    // Deterministic mode for stable CI runs
    if (config.deterministicMode) {
        initDeterministic(config.deterministicSeed);
        logger.info(`Deterministic mode enabled (seed=${config.deterministicSeed})`);
    }

    // Override activeScanning if --active flag is present
    if (activeFlag) {
        (config as { activeScanning: boolean }).activeScanning = true;
    }

    // Guardrails for active scanning
    const allowlist = config.activeScanAllowlist || [];
    if (config.activeScanning) {
        if (!config.activeScanAllowed) {
            logger.warn('Active scanning requested but ACTIVE_SCAN_ALLOWED=false. Disabling active scan.');
            (config as { activeScanning: boolean }).activeScanning = false;
        } else if (allowlist.length > 0) {
            const allowed = allowlist.some(allowedTarget => {
                return config.LIVE_URL.includes(allowedTarget) || allowedTarget === config.LIVE_URL;
            });
            if (!allowed) {
                logger.warn('Active scanning requested but target not in ACTIVE_SCAN_ALLOWLIST. Disabling active scan.');
                (config as { activeScanning: boolean }).activeScanning = false;
            }
        }
    }

    // Apply debug mode overrides from CLI flags
    if (headedFlag || debugFlag) {
        config.DEBUG_HEADED = true;
        logger.info('🔍 Debug: Headed mode enabled');
    }
    if (debugFlag) {
        config.DEBUG_DEVTOOLS = true;
        config.DEBUG_PAUSE_ON_FAILURE = true;
        config.DEBUG_CAPTURE_CONSOLE = true;
        logger.info('🔍 Debug: Full debug mode enabled (devtools + pause on failure)');
    }
    if (slowMoValue > 0) {
        config.DEBUG_SLOW_MO = slowMoValue;
        logger.info(`🔍 Debug: SlowMo set to ${slowMoValue}ms`);
    }

    logger.info(`Loaded Profile: ${config.name}`);
    logger.info(`Active Scanning: ${config.activeScanning ? 'ENABLED ⚠️' : 'Disabled'}`);


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

            const progress = new ProgressReporter(`Target ${i + 1}/${targets.length}`);
            const result = await runner.run(target, progress);
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
        if (v3Flags.sarif || v3Flags.policy || v3Flags.compliance) {
            logSection('v3 Feature Processing');
            
            // Load the fleet summary JSON to get detailed findings
            const fleetSummaryPath = path.join(config.REPORTS_DIR, 'fleet-summary.json');
            if (fs.existsSync(fleetSummaryPath)) {
                try {
                    const summaryData = JSON.parse(fs.readFileSync(fleetSummaryPath, 'utf-8'));
                    
                    // Convert fleet summary to AuditReport format for v3 processing
                    const syntheticReport = {
                        timestamp: new Date().toISOString(),
                        targetUrl: targets[0] || '',
                        duration: totalDuration,
                        performance: { score: summaryData.summary?.averageScore || 0, firstContentfulPaint: 0, largestContentfulPaint: 0, totalBlockingTime: 0, cumulativeLayoutShift: 0, speedIndex: 0, timeToInteractive: 0 },
                        accessibility: { score: 0, issues: [] },
                        security: { score: 0, headers: [], alerts: [], passiveOnly: true },
                        userFlows: [],
                        overallScore: summaryData.summary?.averageScore || 0,
                        passed: !anyFailures,
                    };

                    // SARIF generation
                    if (v3Flags.sarif) {
                        const sarifPath = v3Flags.sarifPath || path.join(config.REPORTS_DIR, 'results.sarif');
                        const findings = v3Service.convertToFindings(syntheticReport);
                        const metadata = {
                            targetUrl: targets[0] || '',
                            startTime: new Date(Date.now() - totalDuration).toISOString(),
                            endTime: new Date().toISOString(),
                            version: V3_VERSION,
                            profile: profileName,
                        };
                        const sarifReporter = new (await import('./v3/reporters/SarifReporter.js')).SarifReporter();
                        const sarifLog = sarifReporter.generate(findings, metadata);
                        
                        // Ensure directory exists
                        const sarifDir = path.dirname(sarifPath);
                        if (!fs.existsSync(sarifDir)) {
                            fs.mkdirSync(sarifDir, { recursive: true });
                        }
                        fs.writeFileSync(sarifPath, JSON.stringify(sarifLog, null, 2));
                        logSuccess(`SARIF report: ${sarifPath}`);
                    }

                    // Policy evaluation
                    if (v3Flags.policy && v3Flags.policyPath) {
                        try {
                            const findings = v3Service.convertToFindings(syntheticReport);
                            const { PolicyEngine } = await import('./v3/core/PolicyEngine.js');
                            const policyEngine = new PolicyEngine();
                            policyEngine.loadFromFile(v3Flags.policyPath);
                            
                            const policyContext = {
                                findings: findings.map(f => ({ id: f.id, type: f.type, severity: f.severity, title: f.title })),
                                meta: { targetUrl: targets[0] || '', scanProfile: profileName, duration: totalDuration, timestamp: new Date().toISOString() },
                            };
                            const policyResult = policyEngine.evaluate(policyContext);
                            
                            if (policyResult.passed) {
                                logSuccess(`Policy evaluation PASSED (${policyResult.passedPolicies.length} policies)`);
                            } else {
                                logFailure(`Policy evaluation FAILED: ${policyResult.failedPolicies.length} policies violated`);
                                exitCode = Math.max(exitCode, policyResult.exitCode);
                            }
                        } catch (policyError) {
                            logger.error(`Policy evaluation failed: ${policyError instanceof Error ? policyError.message : String(policyError)}`);
                        }
                    }

                    // Compliance mapping
                    if (v3Flags.compliance && v3Flags.complianceFrameworks.length > 0) {
                        const findings = v3Service.convertToFindings(syntheticReport);
                        const complianceResult = v3Service.mapCompliance(
                            findings,
                            v3Flags.complianceFrameworks.filter(f => f === 'soc2' || f === 'gdpr' || f === 'hipaa') as ('soc2' | 'gdpr' | 'hipaa')[]
                        );
                        v3Service.printComplianceSummary(complianceResult);
                    }
                } catch (v3Error) {
                    logger.error(`v3 processing failed: ${v3Error instanceof Error ? v3Error.message : String(v3Error)}`);
                }
            } else {
                logger.warn('Fleet summary not found, skipping v3 processing');
            }
        }

        process.exitCode = exitCode;

    } catch (error) {
        logFailure(`Fatal Fleet Error: ${error}`);
        process.exitCode = 2;
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

main();
