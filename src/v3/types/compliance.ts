/**
 * Compliance Framework Type Definitions
 * Maps findings to SOC2, GDPR, HIPAA controls
 */

/**
 * Supported compliance frameworks
 */
export type ComplianceFramework = 'soc2' | 'gdpr' | 'hipaa' | 'pci-dss' | 'iso27001';

/**
 * A control within a compliance framework
 */
export interface ComplianceControl {
    /** Control identifier (e.g., "CC6.1" for SOC2) */
    id: string;
    /** Human-readable title */
    title: string;
    /** Detailed description */
    description: string;
    /** LSCM check IDs that map to this control */
    checks: string[];
    /** Control category/family */
    category?: string;
    /** Reference URL to official documentation */
    referenceUrl?: string;
}

/**
 * Framework definition with all controls
 */
export interface ComplianceFrameworkDefinition {
    id: ComplianceFramework;
    name: string;
    version: string;
    description: string;
    controls: Record<string, ComplianceControl>;
}

/**
 * Result of compliance check for a single control
 */
export interface ComplianceControlResult {
    framework: ComplianceFramework;
    controlId: string;
    control: ComplianceControl;
    /** Whether the control passed */
    passed: boolean;
    /** Findings that caused the control to fail */
    failingFindings: ComplianceFinding[];
    /** Percentage of checks that passed (0-100) */
    score: number;
}

/**
 * Finding associated with compliance control
 */
export interface ComplianceFinding {
    id: string;
    type: string;
    severity: string;
    title: string;
    description: string;
    url?: string;
    remediation?: string;
}

/**
 * Overall compliance report for a framework
 */
export interface ComplianceReport {
    framework: ComplianceFramework;
    frameworkName: string;
    /** Whether overall compliance is achieved */
    compliant: boolean;
    /** Overall compliance score (0-100) */
    score: number;
    /** Results for each control */
    controlResults: ComplianceControlResult[];
    /** Summary counts */
    summary: {
        totalControls: number;
        passingControls: number;
        failingControls: number;
        notApplicable: number;
    };
    /** Timestamp of evaluation */
    evaluatedAt: string;
}

/**
 * Mapping from LSCM finding types to compliance controls
 */
export interface FindingToControlMapping {
    findingType: string;
    frameworks: {
        framework: ComplianceFramework;
        controls: string[];
    }[];
}

/**
 * Enriched finding with compliance information
 */
export interface ComplianceEnrichedFinding {
    /** Original finding ID */
    id: string;
    /** Original finding data */
    finding: ComplianceFinding;
    /** Compliance mappings */
    complianceMappings: {
        framework: ComplianceFramework;
        controlIds: string[];
    }[];
}
