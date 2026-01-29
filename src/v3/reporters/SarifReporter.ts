/**
 * SARIF Reporter
 * Converts LSCM findings to SARIF 2.1.0 format for GitHub Code Scanning
 */

import type {
    SarifLog,
    SarifRun,
    SarifResult,
    SarifReportingDescriptor,
    SarifLevel,
} from '../types/sarif.js';
import { severityToSarifLevel, severityToSecurityScore } from '../types/sarif.js';
import { generateFingerprint as cryptoGenerateFingerprint, generateHash } from '../utils/crypto.js';

/**
 * Generic finding interface that can be mapped to SARIF
 * This abstracts over the various finding types in LSCM
 */
export interface LscmFinding {
    id: string;
    type: string;
    title: string;
    description: string;
    severity: string;
    url?: string;
    selector?: string;
    solution?: string;
    helpUrl?: string;
    category?: string;
    cweId?: string;
}

/**
 * Scan metadata for SARIF invocation
 */
export interface ScanMetadata {
    targetUrl: string;
    startTime: string;
    endTime: string;
    version: string;
    profile: string;
}

/**
 * SARIF Reporter configuration
 */
export interface SarifReporterOptions {
    /** Include related locations for context */
    includeRelatedLocations?: boolean;
    /** Include fingerprints for deduplication */
    includeFingerprints?: boolean;
    /** Base URI for artifact locations */
    baseUri?: string;
}

/**
 * Generates SARIF 2.1.0 reports from LSCM findings
 */
export class SarifReporter {
    private readonly toolName = 'Stealth Compliance Monitor';
    private readonly toolInfoUri = 'https://github.com/Cognostra/Stealth-Compliance-Monitor';
    private readonly schemaUri = 'https://json.schemastore.org/sarif-2.1.0.json';

    private options: SarifReporterOptions;
    private ruleIndex: Map<string, number> = new Map();

    constructor(options: SarifReporterOptions = {}) {
        this.options = {
            includeRelatedLocations: true,
            includeFingerprints: true,
            ...options,
        };
    }

    /**
     * Generate a complete SARIF log from findings
     */
    generate(findings: LscmFinding[], metadata: ScanMetadata): SarifLog {
        const rules = this.buildRules(findings);
        const results = this.buildResults(findings, metadata.targetUrl);

        const run: SarifRun = {
            tool: {
                driver: {
                    name: this.toolName,
                    version: metadata.version,
                    semanticVersion: metadata.version,
                    informationUri: this.toolInfoUri,
                    rules,
                },
            },
            results,
            invocations: [
                {
                    executionSuccessful: true,
                    startTimeUtc: metadata.startTime,
                    endTimeUtc: metadata.endTime,
                },
            ],
        };

        return {
            $schema: this.schemaUri,
            version: '2.1.0',
            runs: [run],
        };
    }

    /**
     * Build SARIF rules from unique finding types
     */
    private buildRules(findings: LscmFinding[]): SarifReportingDescriptor[] {
        const ruleMap = new Map<string, SarifReportingDescriptor>();

        for (const finding of findings) {
            const ruleId = this.getRuleId(finding);

            if (!ruleMap.has(ruleId)) {
                const rule: SarifReportingDescriptor = {
                    id: ruleId,
                    name: finding.type,
                    shortDescription: {
                        text: finding.title,
                    },
                    fullDescription: {
                        text: finding.description,
                    },
                    helpUri: finding.helpUrl,
                    defaultConfiguration: {
                        level: this.getSarifLevel(finding.severity),
                    },
                    properties: {
                        'security-severity': severityToSecurityScore[finding.severity.toLowerCase()] || '0.0',
                        category: finding.category || 'security',
                    },
                };

                if (finding.cweId) {
                    rule.properties = {
                        ...rule.properties,
                        tags: [`CWE-${finding.cweId}`, 'security'],
                    };
                }

                ruleMap.set(ruleId, rule);
            }
        }

        // Build rule index for results
        let index = 0;
        for (const [ruleId] of ruleMap) {
            this.ruleIndex.set(ruleId, index++);
        }

        return Array.from(ruleMap.values());
    }

    /**
     * Build SARIF results from findings
     */
    private buildResults(findings: LscmFinding[], baseUrl: string): SarifResult[] {
        return findings.map((finding) => {
            const ruleId = this.getRuleId(finding);
            const artifactUri = this.urlToArtifactUri(finding.url || baseUrl);

            const result: SarifResult = {
                ruleId,
                ruleIndex: this.ruleIndex.get(ruleId),
                level: this.getSarifLevel(finding.severity),
                message: {
                    text: finding.description,
                    markdown: this.buildMarkdownMessage(finding),
                },
                locations: [
                    {
                        physicalLocation: {
                            artifactLocation: {
                                uri: artifactUri,
                            },
                            region: {
                                startLine: this.selectorToLine(finding.selector),
                                startColumn: 1,
                            },
                        },
                        message: finding.selector
                            ? { text: `Selector: ${finding.selector}` }
                            : undefined,
                    },
                ],
                properties: {
                    severity: finding.severity,
                    category: finding.category || 'security',
                    'security-severity': severityToSecurityScore[finding.severity.toLowerCase()] || '0.0',
                },
            };

            // Add fingerprint for deduplication
            if (this.options.includeFingerprints) {
                result.fingerprints = {
                    'lscm/v1': this.generateFingerprint(finding),
                };
            }

            return result;
        });
    }

    /**
     * Convert URL to SARIF artifact URI
     * e.g., https://example.com/admin/users → example.com/admin/users
     */
    private urlToArtifactUri(url: string): string {
        try {
            const parsed = new URL(url);
            let path = parsed.pathname;

            // Only add index.html for root path or paths ending in /
            if (path === '/' || path === '') {
                path = '/index.html';
            } else if (path.endsWith('/')) {
                path = path + 'index.html';
            }

            return `${parsed.hostname}${path}`;
        } catch {
            // Not a valid URL, use as-is
            return url;
        }
    }

    /**
     * Convert CSS selector to a pseudo line number
     *
     * Uses secure hash for consistent mapping.
     * Replaces weak Java-style hash with SHA-256.
     */
    private selectorToLine(selector?: string): number {
        if (!selector) return 1;

        // Use secure hash and convert to line number
        const hash = generateHash(selector, 'sha256', 'hex');
        // Take first 8 chars of hash and convert to number
        const numericHash = parseInt(hash.substring(0, 8), 16);

        // Return positive number, minimum 1, max 9999
        return (numericHash % 9999) + 1;
    }

    /**
     * Generate unique rule ID from finding
     */
    private getRuleId(finding: LscmFinding): string {
        const type = finding.type
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');

        return `lscm/${type}`;
    }

    /**
     * Map severity to SARIF level
     */
    private getSarifLevel(severity: string): SarifLevel {
        return severityToSarifLevel[severity.toLowerCase()] || 'note';
    }

    /**
     * Build rich markdown message for finding
     */
    private buildMarkdownMessage(finding: LscmFinding): string {
        const parts: string[] = [finding.description];

        if (finding.url) {
            parts.push(`\n\n**URL:** ${finding.url}`);
        }

        if (finding.selector) {
            parts.push(`\n\n**Selector:** \`${finding.selector}\``);
        }

        if (finding.solution) {
            parts.push(`\n\n**Remediation:** ${finding.solution}`);
        }

        return parts.join('');
    }

    /**
     * Generate fingerprint for finding deduplication
     *
     * Uses SHA-256 for collision resistance and security.
     * Replaces weak Java-style hash with cryptographic hash.
     */
    private generateFingerprint(finding: LscmFinding): string {
        const parts = [
            finding.type,
            finding.url || '',
            finding.selector || '',
        ];

        // Use secure SHA-256 hashing
        return cryptoGenerateFingerprint(parts, 8);
    }

    /**
     * Serialize SARIF log to JSON string
     */
    static toJson(log: SarifLog, pretty = true): string {
        return JSON.stringify(log, null, pretty ? 2 : undefined);
    }
}

export default SarifReporter;
