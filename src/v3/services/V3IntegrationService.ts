/**
 * V3 Integration Service
 * Connects audit results with v3 features: SARIF output, policy evaluation, compliance mapping
 */

import * as fs from 'fs';
import * as path from 'path';
import { SarifReporter, type LscmFinding, type ScanMetadata } from '../reporters/SarifReporter.js';
import { PolicyEngine } from '../core/PolicyEngine.js';
import { complianceFrameworks } from '../compliance/frameworks.js';
import type { PolicyEvaluationContext, PolicyEvaluationResult, PolicyMatchedFinding } from '../types/policy.js';
import type { ComplianceFrameworkDefinition, ComplianceControl } from '../types/compliance.js';
import type { AuditReport, SecurityAlert, AccessibilityIssue } from '../../types/index.js';
import { logger } from '../../utils/logger.js';
import { generateId as cryptoGenerateId } from '../utils/crypto.js';

/**
 * Framework IDs we support
 */
export type FrameworkId = 'soc2' | 'gdpr' | 'hipaa';

/**
 * V3 CLI Flags
 */
export interface V3Flags {
    /** Output SARIF file path (empty string means to reports dir, undefined means disabled) */
    sarif?: string;
    /** Policy YAML file path */
    policy?: string;
    /** Compliance frameworks to map */
    compliance?: FrameworkId[];
}

/**
 * Result for a single control evaluation
 */
export interface ControlResult {
    control: ComplianceControl;
    passed: boolean;
    findings: { id: string; type: string; title: string; severity: string }[];
}

/**
 * Result for a framework evaluation
 */
export interface FrameworkResult {
    framework: ComplianceFrameworkDefinition;
    controlResults: ControlResult[];
    passedControls: number;
    totalControls: number;
    compliancePercentage: number;
}

/**
 * Overall compliance result
 */
export interface ComplianceResult {
    timestamp: string;
    frameworks: FrameworkResult[];
    overallCompliance: number;
}

/**
 * V3 processing results
 */
export interface V3ProcessingResult {
    sarif?: {
        path?: string;
        log: unknown;
    };
    policy?: PolicyEvaluationResult;
    compliance?: ComplianceResult;
}

/**
 * Service that integrates v3 features with existing audit results
 */
export class V3IntegrationService {
    private sarifReporter: SarifReporter;
    private policyEngine: PolicyEngine;

    constructor() {
        this.sarifReporter = new SarifReporter();
        this.policyEngine = new PolicyEngine();
    }

    /**
     * Parse v3 CLI flags from command-line arguments
     */
    static parseFlags(args: string[]): V3Flags {
        const flags: V3Flags = {};

        // --sarif or --sarif=path
        const sarifArg = args.find((arg) => arg.startsWith('--sarif'));
        if (sarifArg) {
            if (sarifArg.includes('=')) {
                flags.sarif = sarifArg.split('=')[1];
            } else {
                // --sarif without path means output to reports dir
                flags.sarif = '';
            }
        }

        // --policy=path
        const policyArg = args.find((arg) => arg.startsWith('--policy='));
        if (policyArg) {
            flags.policy = policyArg.split('=')[1];
        }

        // --compliance=soc2,gdpr,hipaa
        const complianceArg = args.find((arg) => arg.startsWith('--compliance='));
        if (complianceArg) {
            const frameworks = complianceArg.split('=')[1].split(',').map((f) => f.trim().toLowerCase());
            flags.compliance = frameworks.filter(
                (f) => f === 'soc2' || f === 'gdpr' || f === 'hipaa'
            ) as FrameworkId[];
        }

        return flags;
    }

    /**
     * Process audit results with v3 features
     */
    async process(
        auditReport: AuditReport,
        flags: V3Flags,
        reportsDir: string
    ): Promise<V3ProcessingResult> {
        const result: V3ProcessingResult = {};

        // Convert audit findings to LSCM format
        const findings = this.convertToFindings(auditReport);

        // Generate SARIF if requested
        if (flags.sarif !== undefined) {
            result.sarif = await this.generateSarif(auditReport, findings, flags.sarif, reportsDir);
        }

        // Evaluate policies if requested
        if (flags.policy) {
            result.policy = await this.evaluatePolicies(auditReport, findings, flags.policy);
        }

        // Map to compliance frameworks if requested
        if (flags.compliance && flags.compliance.length > 0) {
            result.compliance = this.mapCompliance(findings, flags.compliance);
        }

        return result;
    }

    /**
     * Convert audit report findings to unified LscmFinding format
     */
    convertToFindings(report: AuditReport): LscmFinding[] {
        const findings: LscmFinding[] = [];

        // Convert security alerts
        for (const alert of report.security.alerts) {
            findings.push(this.securityAlertToFinding(alert, report.targetUrl));
        }

        // Convert accessibility issues
        for (const issue of report.accessibility.issues) {
            findings.push(this.accessibilityIssueToFinding(issue, report.targetUrl));
        }

        // Add header findings
        for (const header of report.security.headers) {
            if (!header.present) {
                findings.push({
                    id: `header-${header.name}`,
                    type: 'missing-hsts', // Generic header type for categorization
                    title: `Missing Security Header: ${header.name}`,
                    description: header.recommendation || `The ${header.name} header is not set`,
                    severity: this.headerToSeverity(header.name),
                    url: report.targetUrl,
                    category: 'security',
                });
            }
        }

        return findings;
    }

    /**
     * Convert SecurityAlert to LscmFinding
     */
    private securityAlertToFinding(alert: SecurityAlert, targetUrl: string): LscmFinding {
        return {
            id: `zap-${this.generateId(alert.name, alert.url)}`,
            type: this.alertNameToType(alert.name),
            title: alert.name,
            description: alert.description,
            severity: alert.risk.toLowerCase(),
            url: alert.url || targetUrl,
            solution: alert.solution,
            category: 'security',
        };
    }

    /**
     * Convert AccessibilityIssue to LscmFinding
     */
    private accessibilityIssueToFinding(issue: AccessibilityIssue, targetUrl: string): LscmFinding {
        return {
            id: `a11y-${issue.id}`,
            type: `a11y-${issue.id}`,
            title: issue.id.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
            description: issue.description,
            severity: this.a11yImpactToSeverity(issue.impact),
            url: targetUrl,
            helpUrl: issue.helpUrl,
            category: 'accessibility',
        };
    }

    /**
     * Map alert name to standardized finding type
     */
    private alertNameToType(name: string): string {
        const typeMap: Record<string, string> = {
            'Cross-Site Scripting': 'xss',
            'XSS': 'xss',
            'SQL Injection': 'sqli',
            'CSRF': 'csrf',
            'Authentication': 'auth-bypass',
            'Server Leaks': 'info-disclosure',
            'Path Traversal': 'path-traversal',
            'Remote Code Execution': 'rce',
            'IDOR': 'idor',
            'Cookie': 'insecure-cookie',
            'TLS': 'weak-tls',
        };

        for (const [key, type] of Object.entries(typeMap)) {
            if (name.toLowerCase().includes(key.toLowerCase())) {
                return type;
            }
        }

        // Default: slugify the name
        return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    }

    /**
     * Convert a11y impact to severity
     */
    private a11yImpactToSeverity(impact: string): string {
        switch (impact) {
            case 'critical':
                return 'high';
            case 'serious':
                return 'medium';
            case 'moderate':
                return 'low';
            case 'minor':
                return 'low';
            default:
                return 'low';
        }
    }

    /**
     * Get severity for missing security header
     */
    private headerToSeverity(headerName: string): string {
        const highPriority = ['strict-transport-security', 'content-security-policy'];
        const mediumPriority = ['x-frame-options', 'x-content-type-options'];
        
        if (highPriority.includes(headerName.toLowerCase())) return 'high';
        if (mediumPriority.includes(headerName.toLowerCase())) return 'medium';
        return 'low';
    }

    /**
     * Generate a unique ID from name and URL
     *
     * Uses SHA-256 for collision resistance.
     * Replaces weak Java-style hash with cryptographic hash.
     */
    private generateId(name: string, url?: string): string {
        return cryptoGenerateId(name, url);
    }

    /**
     * Generate SARIF output
     */
    private async generateSarif(
        report: AuditReport,
        findings: LscmFinding[],
        outputPath: string,
        reportsDir: string
    ): Promise<{ path?: string; log: unknown }> {
        const metadata: ScanMetadata = {
            targetUrl: report.targetUrl,
            startTime: new Date(new Date(report.timestamp).getTime() - report.duration).toISOString(),
            endTime: report.timestamp,
            version: '3.0.0',
            profile: 'standard',
        };

        const sarifLog = this.sarifReporter.generate(findings, metadata);
        const json = SarifReporter.toJson(sarifLog, true);

        // Determine output path
        let finalPath: string | undefined;
        if (outputPath === '') {
            // Default to reports directory
            finalPath = path.join(reportsDir, 'results.sarif');
        } else if (outputPath) {
            finalPath = path.isAbsolute(outputPath) ? outputPath : path.join(reportsDir, outputPath);
        }

        if (finalPath) {
            // Ensure directory exists
            const dir = path.dirname(finalPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(finalPath, json, 'utf-8');
            logger.info(`SARIF report generated: ${finalPath}`);
        }

        return { path: finalPath, log: sarifLog };
    }

    /**
     * Evaluate policies against findings
     */
    private async evaluatePolicies(
        report: AuditReport,
        findings: LscmFinding[],
        policyPath: string
    ): Promise<PolicyEvaluationResult> {
        // Load policy file
        this.policyEngine.loadFromFile(policyPath);

        // Build evaluation context
        const context: PolicyEvaluationContext = {
            findings: findings.map((f) => this.findingToPolicyFormat(f)),
            meta: {
                targetUrl: report.targetUrl,
                scanProfile: 'standard',
                duration: report.duration,
                timestamp: report.timestamp,
            },
            lighthouse: {
                performance: report.performance.score,
                accessibility: report.accessibility.score,
                seo: 0, // Not in current report
                bestPractices: 0,
            },
            security: this.countSecurityFindings(findings),
        };

        const result = this.policyEngine.evaluate(context);

        // Log results
        if (result.passed) {
            logger.info(`Policy evaluation PASSED (${result.passedPolicies.length} policies)`);
        } else {
            logger.warn(`Policy evaluation FAILED: ${result.failedPolicies.length} policies violated`);
            for (const failed of result.failedPolicies) {
                logger.warn(`  - ${failed.policy.name}: ${failed.matchedFindings.length} matches`);
            }
        }

        return result;
    }

    /**
     * Convert LscmFinding to PolicyMatchedFinding format
     */
    private findingToPolicyFormat(finding: LscmFinding): PolicyMatchedFinding {
        return {
            id: finding.id,
            type: finding.type,
            severity: finding.severity,
            title: finding.title,
            url: finding.url,
            selector: finding.selector,
        };
    }

    /**
     * Count security findings by severity
     */
    private countSecurityFindings(findings: LscmFinding[]): {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
    } {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        for (const f of findings) {
            counts.total++;
            switch (f.severity.toLowerCase()) {
                case 'critical':
                    counts.critical++;
                    break;
                case 'high':
                    counts.high++;
                    break;
                case 'medium':
                    counts.medium++;
                    break;
                default:
                    counts.low++;
            }
        }
        return counts;
    }

    /**
     * Map findings to compliance frameworks
     */
    mapCompliance(findings: LscmFinding[], frameworks: FrameworkId[]): ComplianceResult {
        const result: ComplianceResult = {
            timestamp: new Date().toISOString(),
            frameworks: [],
            overallCompliance: 0,
        };

        for (const frameworkId of frameworks) {
            const framework = complianceFrameworks[frameworkId];
            if (!framework) continue;

            const controlResults: ControlResult[] = [];
            let passed = 0;
            let total = 0;

            for (const control of Object.values(framework.controls)) {
                total++;
                
                // Find findings that match this control
                const matchingFindings: LscmFinding[] = [];
                for (const finding of findings) {
                    if (control.checks.includes(finding.type)) {
                        matchingFindings.push(finding);
                    }
                }

                const isPassed = matchingFindings.length === 0;
                if (isPassed) passed++;

                controlResults.push({
                    control,
                    passed: isPassed,
                    findings: matchingFindings.map((f) => ({
                        id: f.id,
                        type: f.type,
                        title: f.title,
                        severity: f.severity,
                    })),
                });
            }

            result.frameworks.push({
                framework,
                controlResults,
                passedControls: passed,
                totalControls: total,
                compliancePercentage: Math.round((passed / total) * 100),
            });
        }

        // Calculate overall compliance
        const totalPassed = result.frameworks.reduce((acc: number, f: FrameworkResult) => acc + f.passedControls, 0);
        const totalControls = result.frameworks.reduce((acc: number, f: FrameworkResult) => acc + f.totalControls, 0);
        result.overallCompliance = totalControls > 0 ? Math.round((totalPassed / totalControls) * 100) : 100;

        // Log results
        for (const fr of result.frameworks) {
            logger.info(`${fr.framework.name}: ${fr.compliancePercentage}% compliant (${fr.passedControls}/${fr.totalControls} controls)`);
        }

        return result;
    }

    /**
     * Print compliance summary to console
     */
    printComplianceSummary(result: ComplianceResult): void {
        console.log('\n╭─────────────────────────────────────────────────────────────────╮');
        console.log('│                    COMPLIANCE SUMMARY                           │');
        console.log('╰─────────────────────────────────────────────────────────────────╯\n');

        for (const fr of result.frameworks) {
            const bar = this.getProgressBar(fr.compliancePercentage);
            console.log(`  ${fr.framework.name.padEnd(25)} ${bar} ${fr.compliancePercentage}%`);
            
            // Show failed controls
            const failed = fr.controlResults.filter((c: ControlResult) => !c.passed);
            if (failed.length > 0) {
                for (const ctrl of failed) {
                    console.log(`    ⚠ ${ctrl.control.id}: ${ctrl.control.title}`);
                }
            }
            console.log('');
        }

        console.log(`  Overall Compliance: ${result.overallCompliance}%`);
    }

    /**
     * Generate ASCII progress bar
     */
    private getProgressBar(percentage: number): string {
        const width = 20;
        const filled = Math.round((percentage / 100) * width);
        const empty = width - filled;
        const bar = '█'.repeat(filled) + '░'.repeat(empty);
        return `[${bar}]`;
    }
}

export default V3IntegrationService;
