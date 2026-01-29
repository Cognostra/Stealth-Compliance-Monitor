
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ComplianceConfig } from '../config/compliance.config.js';
import { V3FeatureFlags, V3IntegrationService, V3_VERSION } from './index.js';
import { TrendService } from './services/TrendService.js';
import { logger, logSuccess, logFailure } from '../utils/logger.js';
import { ExecutiveReportGenerator, ReportData } from '../services/ExecutiveReportGenerator.js';
import { isAuditReport, validateFilePath } from './utils/validation.js';
import type { AuditReport } from '../types/index.js';

export interface V3ProcessingOptions {
    config: ComplianceConfig;
    targets: string[];
    v3Flags: V3FeatureFlags;
    v3Service: V3IntegrationService;
    profileName: string;
    totalDuration: number;
    currentExitCode: number;
    anyFailures: boolean;
    trendService: TrendService;
}

interface FleetSummary {
    summary?: {
        averageScore?: number;
    };
}

// Minimal shape for report data to satisfy V3 features
interface SyntheticReport {
    timestamp: string;
    targetUrl: string;
    duration: number;
    performance: { score: number; [key: string]: unknown };
    accessibility: { score: number; issues: unknown[] };
    security: { score: number; headers: unknown[]; alerts: unknown[]; passiveOnly: boolean };
    userFlows: unknown[];
    overallScore: number;
    passed: boolean;
}

/**
 * Safely convert SyntheticReport to AuditReport
 *
 * Uses type guard to validate structure at runtime before conversion.
 * Replaces unsafe `as any` casts with validated conversion.
 *
 * @param report - The synthetic report to convert
 * @returns Validated AuditReport
 * @throws Error if report structure is invalid
 */
function toAuditReport(report: SyntheticReport): AuditReport {
    // Validate that the report has the required AuditReport structure
    if (!isAuditReport(report)) {
        throw new Error(
            'Invalid report structure: SyntheticReport does not match AuditReport interface. ' +
            'This may indicate a data corruption or incomplete report generation.'
        );
    }

    // TypeScript now knows this is an AuditReport
    return report;
}

export async function processV3Features(options: V3ProcessingOptions): Promise<number> {
    const { config, targets, v3Flags, v3Service, profileName, totalDuration, currentExitCode, anyFailures } = options;
    let exitCode = currentExitCode;
    
    // Load the fleet summary JSON to get detailed findings
    const fleetSummaryPath = path.join(config.REPORTS_DIR, 'fleet-summary.json');
    if (!fs.existsSync(fleetSummaryPath)) {
        logger.warn('Fleet summary not found, skipping v3 processing');
        return exitCode;
    }

    try {
        const summaryData: FleetSummary = JSON.parse(fs.readFileSync(fleetSummaryPath, 'utf-8'));
        
        // Convert fleet summary to AuditReport format for v3 processing
        const syntheticReport = createSyntheticReport(summaryData, targets, totalDuration, anyFailures);

        // SARIF generation
        if (v3Flags.sarif) {
            await generateSarifReport(v3Flags, v3Service, syntheticReport, config, profileName, totalDuration);
        }

        // Policy evaluation
        if (v3Flags.policy && v3Flags.policyPath) {
             exitCode = await evaluatePolicy(v3Flags.policyPath, v3Service, syntheticReport, targets[0], profileName, totalDuration, exitCode);
        }

        // Compliance mapping
        if (v3Flags.compliance && v3Flags.complianceFrameworks.length > 0) {
            processCompliance(v3Flags, v3Service, syntheticReport);
        }

        // Executive Summary
        if (v3Flags.executiveReport) {
            await generateExecutiveReport(options, syntheticReport, config, profileName);
        }

    } catch (v3Error) {
        logger.error(`v3 processing failed: ${v3Error instanceof Error ? v3Error.message : String(v3Error)}`);
    }

    return exitCode;
}

function createSyntheticReport(summaryData: FleetSummary, targets: string[], totalDuration: number, anyFailures: boolean): SyntheticReport {
    return {
        timestamp: new Date().toISOString(),
        targetUrl: targets[0] || '', // Primary target for context
        duration: totalDuration,
        performance: { 
            score: summaryData.summary?.averageScore || 0, 
            firstContentfulPaint: 0, 
            largestContentfulPaint: 0, 
            totalBlockingTime: 0, 
            cumulativeLayoutShift: 0, 
            speedIndex: 0, 
            timeToInteractive: 0 
        },
        accessibility: { score: 0, issues: [] },
        security: { score: 0, headers: [], alerts: [], passiveOnly: true },
        userFlows: [],
        overallScore: summaryData.summary?.averageScore || 0,
        passed: !anyFailures,
    };
}

async function generateSarifReport(v3Flags: V3FeatureFlags, v3Service: V3IntegrationService, syntheticReport: SyntheticReport, config: ComplianceConfig, profileName: string, totalDuration: number) {
    const sarifPath = v3Flags.sarifPath || path.join(config.REPORTS_DIR, 'results.sarif');

    // Validate SARIF output path to prevent path traversal
    const pathValidation = validateFilePath(sarifPath, {
        allowedDirs: [config.REPORTS_DIR, path.resolve(config.REPORTS_DIR)],
        requiredExtensions: ['.sarif', '.json'],
        mustExist: false, // File doesn't exist yet
    });

    if (!pathValidation.valid) {
        throw new Error(`SARIF path validation failed: ${pathValidation.error}`);
    }

    // Use the validated normalized path
    const validatedSarifPath = pathValidation.normalizedPath!;

    // Use safe conversion with runtime validation
    const auditReport = toAuditReport(syntheticReport);
    const findings = v3Service.convertToFindings(auditReport);
    const metadata = {
        targetUrl: syntheticReport.targetUrl,
        startTime: new Date(Date.now() - totalDuration).toISOString(),
        endTime: new Date().toISOString(),
        version: V3_VERSION,
        profile: profileName,
    };
    const sarifReporter = new (await import('./reporters/SarifReporter.js')).SarifReporter();
    const sarifLog = sarifReporter.generate(findings, metadata);

    // Ensure directory exists
    const sarifDir = path.dirname(validatedSarifPath);
    if (!fs.existsSync(sarifDir)) {
        fs.mkdirSync(sarifDir, { recursive: true });
    }
    fs.writeFileSync(validatedSarifPath, JSON.stringify(sarifLog, null, 2));
    logSuccess(`SARIF report: ${validatedSarifPath}`);
}

async function evaluatePolicy(policyPath: string, v3Service: V3IntegrationService, syntheticReport: SyntheticReport, targetUrl: string, profileName: string, totalDuration: number, currentExitCode: number): Promise<number> {
    try {
        // Use safe conversion with runtime validation
        const auditReport = toAuditReport(syntheticReport);
        const findings = v3Service.convertToFindings(auditReport);
        const { PolicyEngine } = await import('./core/PolicyEngine.js');
        const policyEngine = new PolicyEngine();
        policyEngine.loadFromFile(policyPath);
        
        const policyContext = {
            findings: findings.map(f => ({ id: f.id, type: f.type, severity: f.severity, title: f.title })),
            meta: { targetUrl: targetUrl || '', scanProfile: profileName, duration: totalDuration, timestamp: new Date().toISOString() },
        };
        const policyResult = policyEngine.evaluate(policyContext);
        
        if (policyResult.passed) {
            logSuccess(`Policy evaluation PASSED (${policyResult.passedPolicies.length} policies)`);
        } else {
            logFailure(`Policy evaluation FAILED: ${policyResult.failedPolicies.length} policies violated`);
            return Math.max(currentExitCode, policyResult.exitCode);
        }
    } catch (policyError) {
        logger.error(`Policy evaluation failed: ${policyError instanceof Error ? policyError.message : String(policyError)}`);
    }
    return currentExitCode;
}

function processCompliance(v3Flags: V3FeatureFlags, v3Service: V3IntegrationService, syntheticReport: SyntheticReport) {
    // Use safe conversion with runtime validation
    const auditReport = toAuditReport(syntheticReport);
    const findings = v3Service.convertToFindings(auditReport);
    
    // Use Set for optimized lookups
    const validFrameworks = new Set(['soc2', 'gdpr', 'hipaa']);
    const frameworks = v3Flags.complianceFrameworks.filter(f => validFrameworks.has(f)) as ('soc2' | 'gdpr' | 'hipaa')[];
    
    const complianceResult = v3Service.mapCompliance(findings, frameworks);
    v3Service.printComplianceSummary(complianceResult);
}

async function generateExecutiveReport(options: V3ProcessingOptions, syntheticReport: SyntheticReport, config: ComplianceConfig, profileName: string) {
    try {
        const execGenerator = new ExecutiveReportGenerator(config.REPORTS_DIR);
        const execData: ReportData = {
            meta: {
                version: V3_VERSION,
                generatedAt: syntheticReport.timestamp,
                targetUrl: syntheticReport.targetUrl,
                scanType: profileName,
                duration: syntheticReport.duration
            },
            lighthouse: {
                scores: {
                    performance: syntheticReport.performance.score,
                    accessibility: syntheticReport.accessibility.score || 0,
                    bestPractices: 0,
                    seo: 0
                }
            },
            security_alerts: syntheticReport.security.alerts as any[],
            security_assessment: { findings: [] }
        };

        const healthScore = Math.round(syntheticReport.overallScore);
        const history = options.trendService.getHistory(syntheticReport.targetUrl);

        await execGenerator.generateReport(execData, healthScore, history);
    } catch (execError) {
        logger.error(`Executive Report generation failed: ${execError instanceof Error ? execError.message : String(execError)}`);
    }
}
