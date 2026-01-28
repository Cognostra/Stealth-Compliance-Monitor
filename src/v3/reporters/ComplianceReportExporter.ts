/**
 * Compliance Report Exporter
 * Generates markdown compliance reports for audit evidence
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { complianceFrameworks } from '../compliance/frameworks.js';
import type { LscmFinding } from '../reporters/SarifReporter.js';
import type { ComplianceFramework, ComplianceControl, ComplianceFrameworkDefinition } from '../types/compliance.js';

/**
 * Framework control with mapped findings
 */
interface ControlEvidence {
    control: ComplianceControl;
    findings: LscmFinding[];
    status: 'pass' | 'fail' | 'partial';
}

/**
 * Framework compliance summary
 */
interface FrameworkSummary {
    frameworkId: ComplianceFramework;
    frameworkName: string;
    controls: ControlEvidence[];
    passCount: number;
    failCount: number;
    partialCount: number;
    overallStatus: 'compliant' | 'non-compliant' | 'partial';
}

/**
 * Compliance report export options
 */
export interface ComplianceExportOptions {
    frameworks: ComplianceFramework[];
    findings: LscmFinding[];
    outputDir: string;
    targetUrl: string;
    scanDate?: string;
}

/**
 * Compliance Report Exporter
 */
export class ComplianceReportExporter {
    /**
     * Export compliance reports for specified frameworks
     */
    export(options: ComplianceExportOptions): string[] {
        const { frameworks, findings, outputDir, targetUrl, scanDate } = options;
        const exportedFiles: string[] = [];

        for (const frameworkId of frameworks) {
            const summary = this.buildFrameworkSummary(frameworkId, findings);
            const markdown = this.generateMarkdown(summary, targetUrl, scanDate);
            
            const filename = `compliance-${frameworkId}.md`;
            const filepath = path.join(outputDir, filename);
            
            // Ensure directory exists
            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }
            
            fs.writeFileSync(filepath, markdown, 'utf-8');
            exportedFiles.push(filepath);
        }

        return exportedFiles;
    }

    /**
     * Build compliance summary for a framework
     */
    private buildFrameworkSummary(
        frameworkId: ComplianceFramework,
        findings: LscmFinding[]
    ): FrameworkSummary {
        const framework = complianceFrameworks[frameworkId as keyof typeof complianceFrameworks];
        if (!framework) {
            // Framework not implemented yet (e.g., pci-dss, iso27001)
            return {
                frameworkId,
                frameworkName: frameworkId.toUpperCase(),
                controls: [],
                passCount: 0,
                failCount: 0,
                partialCount: 0,
                overallStatus: 'partial' as const,
            };
        }
        const controls: ControlEvidence[] = [];
        
        let passCount = 0;
        let failCount = 0;
        let partialCount = 0;

        // Get all controls for this framework
        for (const [controlId, control] of Object.entries(framework.controls) as [string, ComplianceControl][]) {
            // Find findings that match this control's checks
            const matchingFindings = findings.filter(f => 
                control.checks.some((check: string) => 
                    f.type.toLowerCase().includes(check.toLowerCase()) ||
                    f.id.toLowerCase().includes(check.toLowerCase())
                )
            );

            // Determine status based on findings
            let status: 'pass' | 'fail' | 'partial' = 'pass';
            
            if (matchingFindings.length > 0) {
                const hasCritical = matchingFindings.some(f => f.severity === 'critical' || f.severity === 'high');
                status = hasCritical ? 'fail' : 'partial';
            }

            if (status === 'pass') passCount++;
            else if (status === 'fail') failCount++;
            else partialCount++;

            controls.push({
                control: { ...control, id: controlId },
                findings: matchingFindings,
                status,
            });
        }

        // Determine overall status
        let overallStatus: 'compliant' | 'non-compliant' | 'partial' = 'compliant';
        if (failCount > 0) {
            overallStatus = 'non-compliant';
        } else if (partialCount > 0) {
            overallStatus = 'partial';
        }

        return {
            frameworkId,
            frameworkName: framework.name,
            controls,
            passCount,
            failCount,
            partialCount,
            overallStatus,
        };
    }

    /**
     * Generate markdown report
     */
    private generateMarkdown(
        summary: FrameworkSummary,
        targetUrl: string,
        scanDate?: string
    ): string {
        const date = scanDate || new Date().toISOString().split('T')[0];
        const statusEmoji = summary.overallStatus === 'compliant' ? '✅' 
            : summary.overallStatus === 'partial' ? '⚠️' : '❌';

        let md = `# ${summary.frameworkName} Compliance Report

**Target:** ${targetUrl}  
**Date:** ${date}  
**Status:** ${statusEmoji} ${summary.overallStatus.toUpperCase()}

---

## Summary

| Metric | Count |
|--------|-------|
| Controls Passing | ${summary.passCount} |
| Controls Failing | ${summary.failCount} |
| Controls Partial | ${summary.partialCount} |
| Total Controls | ${summary.controls.length} |

---

## Control Details

`;

        for (const evidence of summary.controls) {
            const statusIcon = evidence.status === 'pass' ? '✅' 
                : evidence.status === 'partial' ? '⚠️' : '❌';
            
            md += `### ${statusIcon} ${evidence.control.id}: ${evidence.control.title}\n\n`;
            md += `**Description:** ${evidence.control.description}\n\n`;
            
            if (evidence.findings.length > 0) {
                md += `**Findings:**\n\n`;
                md += `| Severity | Type | Title |\n`;
                md += `|----------|------|-------|\n`;
                
                for (const finding of evidence.findings.slice(0, 10)) { // Limit to 10
                    md += `| ${finding.severity} | ${finding.type} | ${finding.title.slice(0, 50)} |\n`;
                }
                
                if (evidence.findings.length > 10) {
                    md += `\n*... and ${evidence.findings.length - 10} more findings*\n`;
                }
            } else {
                md += `**Findings:** None detected ✓\n`;
            }
            
            md += `\n---\n\n`;
        }

        md += `\n*Generated by Stealth Compliance Monitor v3.0*\n`;

        return md;
    }
}

/**
 * Parse export-compliance CLI arguments
 */
export function parseExportComplianceArgs(args: string[]): {
    export: boolean;
    outputDir?: string;
} {
    const exportFlag = args.includes('--export-compliance');
    const outputArg = args.find(a => a.startsWith('--compliance-output='));
    const outputDir = outputArg ? outputArg.split('=')[1] : undefined;

    return { export: exportFlag, outputDir };
}
