/**
 * SARIF 2.1.0 Type Definitions
 * Static Analysis Results Interchange Format
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

export interface SarifLog {
    $schema: string;
    version: '2.1.0';
    runs: SarifRun[];
}

export interface SarifRun {
    tool: SarifTool;
    results: SarifResult[];
    invocations?: SarifInvocation[];
    artifacts?: SarifArtifact[];
}

export interface SarifTool {
    driver: SarifToolComponent;
}

export interface SarifToolComponent {
    name: string;
    version?: string;
    semanticVersion?: string;
    informationUri?: string;
    rules?: SarifReportingDescriptor[];
}

export interface SarifReportingDescriptor {
    id: string;
    name?: string;
    shortDescription?: SarifMultiformatMessage;
    fullDescription?: SarifMultiformatMessage;
    helpUri?: string;
    help?: SarifMultiformatMessage;
    defaultConfiguration?: SarifReportingConfiguration;
    properties?: Record<string, unknown>;
}

export interface SarifMultiformatMessage {
    text: string;
    markdown?: string;
}

export interface SarifReportingConfiguration {
    level?: SarifLevel;
    enabled?: boolean;
}

export type SarifLevel = 'none' | 'note' | 'warning' | 'error';

export interface SarifResult {
    ruleId: string;
    ruleIndex?: number;
    level?: SarifLevel;
    message: SarifMessage;
    locations?: SarifLocation[];
    relatedLocations?: SarifLocation[];
    fingerprints?: Record<string, string>;
    partialFingerprints?: Record<string, string>;
    properties?: SarifResultProperties;
}

export interface SarifResultProperties {
    severity?: string;
    category?: string;
    tags?: string[];
    'security-severity'?: string;
    [key: string]: unknown;
}

export interface SarifMessage {
    text?: string;
    markdown?: string;
    id?: string;
    arguments?: string[];
}

export interface SarifLocation {
    physicalLocation?: SarifPhysicalLocation;
    logicalLocations?: SarifLogicalLocation[];
    message?: SarifMessage;
}

export interface SarifPhysicalLocation {
    artifactLocation: SarifArtifactLocation;
    region?: SarifRegion;
    contextRegion?: SarifRegion;
}

export interface SarifArtifactLocation {
    uri: string;
    uriBaseId?: string;
    index?: number;
}

export interface SarifRegion {
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    snippet?: SarifArtifactContent;
}

export interface SarifArtifactContent {
    text?: string;
    binary?: string;
    rendered?: SarifMultiformatMessage;
}

export interface SarifLogicalLocation {
    name?: string;
    fullyQualifiedName?: string;
    kind?: string;
}

export interface SarifInvocation {
    executionSuccessful: boolean;
    startTimeUtc?: string;
    endTimeUtc?: string;
    workingDirectory?: SarifArtifactLocation;
}

export interface SarifArtifact {
    location: SarifArtifactLocation;
    length?: number;
    mimeType?: string;
}

// Mapping helpers for LSCM severity to SARIF level
export const severityToSarifLevel: Record<string, SarifLevel> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    informational: 'note',
    info: 'note',
};

// Mapping for security-severity scores (CVSS-like 0-10 scale)
export const severityToSecurityScore: Record<string, string> = {
    critical: '9.0',
    high: '7.0',
    medium: '4.0',
    low: '2.0',
    informational: '0.0',
    info: '0.0',
};
