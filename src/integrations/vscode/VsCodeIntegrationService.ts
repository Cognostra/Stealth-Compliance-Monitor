/**
 * VS Code Extension Integration Service
 *
 * Provides integration with VS Code for displaying audit results,
 * running scans from within the editor, and showing diagnostics.
 *
 * Features:
 * - Language Server Protocol (LSP) compatible diagnostics
 * - Workspace trust integration
 * - Custom commands and tree views
 * - Inline problem annotations
 */

import { logger } from '../../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface VsCodeDiagnostic {
    code: string;
    message: string;
    severity: 'error' | 'warning' | 'information' | 'hint';
    range: {
        start: { line: number; character: number };
        end: { line: number; character: number };
    };
    source: string;
    relatedInformation?: Array<{
        message: string;
        location: {
            uri: string;
            range: {
                start: { line: number; character: number };
                end: { line: number; character: number };
            };
        };
    }>;
}

export interface VsCodeCommand {
    command: string;
    title: string;
    tooltip?: string;
    arguments?: unknown[];
}

export interface VsCodeWorkspaceConfig {
    enableLinting: boolean;
    scanOnSave: boolean;
    autoFix: boolean;
    severityThreshold: 'error' | 'warning' | 'information';
    ignorePatterns: string[];
    customRules: Record<string, unknown>;
}

export interface AuditResultExport {
    findings: Array<{
        type: string;
        severity: string;
        message: string;
        file: string;
        line?: number;
        column?: number;
        url?: string;
    }>;
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

export interface VsCodeExtensionManifest {
    name: string;
    version: string;
    publisher: string;
    engines: {
        vscode: string;
    };
    categories: string[];
    keywords: string[];
    activationEvents: string[];
    contributes: {
        commands: Array<{ command: string; title: string; category: string }>;
        menus: Record<string, unknown>;
        views: Record<string, unknown>;
        configuration: {
            title: string;
            properties: Record<string, unknown>;
        };
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class VsCodeIntegrationService {
    private diagnostics: Map<string, VsCodeDiagnostic[]> = new Map();
    private config: VsCodeWorkspaceConfig;

    constructor(config?: Partial<VsCodeWorkspaceConfig>) {
        this.config = {
            enableLinting: true,
            scanOnSave: true,
            autoFix: false,
            severityThreshold: 'warning',
            ignorePatterns: ['node_modules/**', 'dist/**', 'build/**', '.git/**'],
            customRules: {},
            ...config,
        };
    }

    /**
     * Convert audit findings to VS Code diagnostics format.
     */
    convertFindingsToDiagnostics(auditResult: AuditResultExport): Map<string, VsCodeDiagnostic[]> {
        const diagnostics = new Map<string, VsCodeDiagnostic[]>();

        for (const finding of auditResult.findings) {
            const file = finding.file || 'unknown';
            const diagnostic: VsCodeDiagnostic = {
                code: finding.type,
                message: `${finding.type}: ${finding.message}`,
                severity: this.mapSeverity(finding.severity),
                range: {
                    start: {
                        line: (finding.line || 1) - 1,
                        character: finding.column || 0,
                    },
                    end: {
                        line: (finding.line || 1) - 1,
                        character: (finding.column || 0) + 1,
                    },
                },
                source: 'StealthCompliance',
            };

            if (finding.url) {
                diagnostic.relatedInformation = [{
                    message: `URL: ${finding.url}`,
                    location: {
                        uri: finding.url,
                        range: diagnostic.range,
                    },
                }];
            }

            const existing = diagnostics.get(file) || [];
            existing.push(diagnostic);
            diagnostics.set(file, existing);
        }

        this.diagnostics = diagnostics;
        logger.info(`[VsCodeIntegration] Converted ${auditResult.findings.length} findings to diagnostics`);
        return diagnostics;
    }

    /**
     * Get available VS Code commands for the extension.
     */
    getCommands(): VsCodeCommand[] {
        return [
            {
                command: 'stealthCompliance.scanWorkspace',
                title: 'Scan Workspace',
                tooltip: 'Run compliance scan on entire workspace',
            },
            {
                command: 'stealthCompliance.scanFile',
                title: 'Scan Current File',
                tooltip: 'Run compliance scan on current file',
            },
            {
                command: 'stealthCompliance.showReport',
                title: 'Show Audit Report',
                tooltip: 'Display full audit report in sidebar',
            },
            {
                command: 'stealthCompliance.applyFix',
                title: 'Apply Fix',
                tooltip: 'Apply suggested fix for the current finding',
            },
            {
                command: 'stealthCompliance.exportResults',
                title: 'Export Results',
                tooltip: 'Export audit results to various formats',
            },
            {
                command: 'stealthCompliance.configure',
                title: 'Configure Settings',
                tooltip: 'Open Stealth Compliance settings',
            },
        ];
    }

    /**
     * Generate extension manifest for package.json.
     */
    generateManifest(version: string = '0.1.0'): VsCodeExtensionManifest {
        return {
            name: 'stealth-compliance',
            version,
            publisher: 'stealth-security',
            engines: {
                vscode: '^1.74.0',
            },
            categories: ['Testing', 'Linters', 'Other'],
            keywords: ['security', 'compliance', 'audit', 'accessibility', 'privacy', 'gdpr'],
            activationEvents: ['onLanguage:javascript', 'onLanguage:typescript', 'onLanguage:html'],
            contributes: {
                commands: [
                    { command: 'stealthCompliance.scanWorkspace', title: 'Scan Workspace', category: 'Stealth' },
                    { command: 'stealthCompliance.scanFile', title: 'Scan Current File', category: 'Stealth' },
                    { command: 'stealthCompliance.showReport', title: 'Show Report', category: 'Stealth' },
                    { command: 'stealthCompliance.applyFix', title: 'Apply Fix', category: 'Stealth' },
                    { command: 'stealthCompliance.exportResults', title: 'Export Results', category: 'Stealth' },
                ],
                menus: {
                    'editor/context': [
                        { command: 'stealthCompliance.scanFile', group: '9_cutcopypaste@5' },
                    ],
                },
                views: {
                    explorer: [
                        {
                            id: 'stealthComplianceFindings',
                            name: 'Compliance Findings',
                            when: 'stealthCompliance.hasResults',
                        },
                    ],
                },
                configuration: {
                    title: 'Stealth Compliance',
                    properties: {
                        'stealthCompliance.enableLinting': {
                            type: 'boolean',
                            default: true,
                            description: 'Enable inline linting in editor',
                        },
                        'stealthCompliance.scanOnSave': {
                            type: 'boolean',
                            default: true,
                            description: 'Scan files on save',
                        },
                        'stealthCompliance.severityThreshold': {
                            type: 'string',
                            enum: ['error', 'warning', 'information'],
                            default: 'warning',
                            description: 'Minimum severity to show in problems panel',
                        },
                    },
                },
            },
        };
    }

    /**
     * Generate Code Action (quick fix) for a diagnostic.
     */
    generateCodeAction(diagnostic: VsCodeDiagnostic): { title: string; edit: unknown } | null {
        // Map finding types to potential fixes
        const fixes: Record<string, { title: string; replacement: string }> = {
            'missing-csp': {
                title: 'Add Content-Security-Policy header',
                replacement: "Content-Security-Policy: default-src 'self'",
            },
            'missing-alt-text': {
                title: 'Add alt attribute',
                replacement: ' alt="Description"',
            },
            'unsafe-eval': {
                title: 'Remove unsafe-eval from CSP',
                replacement: "",
            },
        };

        const fix = fixes[diagnostic.code];
        if (!fix) return null;

        return {
            title: fix.title,
            edit: {
                changes: {
                    [diagnostic.relatedInformation?.[0]?.location?.uri || '']: [
                        {
                            range: diagnostic.range,
                            newText: fix.replacement,
                        },
                    ],
                },
            },
        };
    }

    /**
     * Check if a file should be ignored based on patterns.
     */
    shouldIgnoreFile(filePath: string): boolean {
        for (const pattern of this.config.ignorePatterns) {
            // Simple glob matching
            const regex = new RegExp(
                pattern
                    .replace(/\*\*/g, '.*')
                    .replace(/\*/g, '[^/]*')
                    .replace(/\?/g, '.')
            );
            if (regex.test(filePath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Update configuration.
     */
    updateConfig(config: Partial<VsCodeWorkspaceConfig>): void {
        this.config = { ...this.config, ...config };
    }

    /**
     * Get current configuration.
     */
    getConfig(): VsCodeWorkspaceConfig {
        return { ...this.config };
    }

    /**
     * Clear all diagnostics.
     */
    clearDiagnostics(): void {
        this.diagnostics.clear();
    }

    /**
     * Get diagnostics for a specific file.
     */
    getDiagnosticsForFile(file: string): VsCodeDiagnostic[] {
        return this.diagnostics.get(file) || [];
    }

    private mapSeverity(severity: string): VsCodeDiagnostic['severity'] {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'error':
                return 'error';
            case 'high':
            case 'warning':
                return 'warning';
            case 'medium':
                return 'information';
            case 'low':
            default:
                return 'hint';
        }
    }
}

export default VsCodeIntegrationService;
