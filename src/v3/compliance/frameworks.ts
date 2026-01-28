/**
 * Compliance Framework Definitions
 * Maps LSCM findings to SOC2, GDPR, HIPAA controls
 */

import type { ComplianceFrameworkDefinition, FindingToControlMapping } from '../types/compliance.js';

/**
 * SOC2 Trust Services Criteria
 * Based on AICPA SOC2 2017 Trust Services Criteria
 */
export const soc2Framework: ComplianceFrameworkDefinition = {
    id: 'soc2',
    name: 'SOC 2 Type II',
    version: '2017',
    description: 'Service Organization Control 2 - Trust Services Criteria',
    controls: {
        'CC6.1': {
            id: 'CC6.1',
            title: 'Logical and Physical Access Controls',
            description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity\'s objectives.',
            category: 'Logical and Physical Access',
            checks: [
                'auth-bypass',
                'idor',
                'csrf',
                'session-fixation',
                'session-hijacking',
                'broken-access-control',
            ],
            referenceUrl: 'https://www.aicpa.org/soc4so',
        },
        'CC6.6': {
            id: 'CC6.6',
            title: 'Vulnerability Management',
            description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity\'s objectives.',
            category: 'Logical and Physical Access',
            checks: [
                'vulnerable-library',
                'zap-high',
                'zap-critical',
                'xss',
                'sqli',
                'command-injection',
                'path-traversal',
            ],
            referenceUrl: 'https://www.aicpa.org/soc4so',
        },
        'CC6.7': {
            id: 'CC6.7',
            title: 'Transmission Protection',
            description: 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.',
            category: 'Logical and Physical Access',
            checks: [
                'missing-hsts',
                'insecure-cookie',
                'mixed-content',
                'missing-secure-flag',
            ],
            referenceUrl: 'https://www.aicpa.org/soc4so',
        },
        'CC7.1': {
            id: 'CC7.1',
            title: 'Detect Security Events',
            description: 'The entity uses detection and monitoring procedures to identify security events.',
            category: 'System Operations',
            checks: [
                'info-disclosure',
                'debug-enabled',
                'error-disclosure',
                'stack-trace-exposure',
            ],
            referenceUrl: 'https://www.aicpa.org/soc4so',
        },
        'CC7.2': {
            id: 'CC7.2',
            title: 'Monitor System Components',
            description: 'The entity monitors system components and the operation of those components for anomalies.',
            category: 'System Operations',
            checks: [
                'console-errors',
                'network-failures',
                'rate-limit-missing',
            ],
            referenceUrl: 'https://www.aicpa.org/soc4so',
        },
    },
};

/**
 * GDPR Articles
 * Based on EU General Data Protection Regulation
 */
export const gdprFramework: ComplianceFrameworkDefinition = {
    id: 'gdpr',
    name: 'GDPR',
    version: '2018',
    description: 'EU General Data Protection Regulation',
    controls: {
        'Art5': {
            id: 'Art5',
            title: 'Principles of Processing',
            description: 'Personal data shall be processed lawfully, fairly and in a transparent manner.',
            category: 'Principles',
            checks: [
                'pii-exposure',
                'cookie-no-consent',
                'privacy-policy-missing',
            ],
            referenceUrl: 'https://gdpr-info.eu/art-5-gdpr/',
        },
        'Art25': {
            id: 'Art25',
            title: 'Data Protection by Design',
            description: 'The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles.',
            category: 'Security',
            checks: [
                'pii-exposure',
                'secrets-leak',
                'sensitive-data-exposure',
            ],
            referenceUrl: 'https://gdpr-info.eu/art-25-gdpr/',
        },
        'Art32': {
            id: 'Art32',
            title: 'Security of Processing',
            description: 'The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.',
            category: 'Security',
            checks: [
                'cookie-security',
                'pii-exposure',
                'secrets-leak',
                'missing-hsts',
                'insecure-cookie',
                'xss',
                'sqli',
                'auth-bypass',
            ],
            referenceUrl: 'https://gdpr-info.eu/art-32-gdpr/',
        },
        'Art33': {
            id: 'Art33',
            title: 'Notification of Breach',
            description: 'In the case of a personal data breach, the controller shall notify the supervisory authority.',
            category: 'Breach Notification',
            checks: [
                'pii-exposure',
                'data-breach-indicators',
            ],
            referenceUrl: 'https://gdpr-info.eu/art-33-gdpr/',
        },
    },
};

/**
 * HIPAA Security Rule
 * Based on 45 CFR Part 164 Subpart C
 */
export const hipaaFramework: ComplianceFrameworkDefinition = {
    id: 'hipaa',
    name: 'HIPAA Security Rule',
    version: '2013',
    description: 'Health Insurance Portability and Accountability Act - Security Rule',
    controls: {
        '164.312(a)': {
            id: '164.312(a)',
            title: 'Access Control',
            description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons.',
            category: 'Technical Safeguards',
            checks: [
                'auth-bypass',
                'idor',
                'broken-access-control',
                'session-fixation',
            ],
            referenceUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
        },
        '164.312(b)': {
            id: '164.312(b)',
            title: 'Audit Controls',
            description: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems.',
            category: 'Technical Safeguards',
            checks: [
                'info-disclosure',
                'debug-enabled',
            ],
            referenceUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
        },
        '164.312(c)': {
            id: '164.312(c)',
            title: 'Integrity Controls',
            description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
            category: 'Technical Safeguards',
            checks: [
                'xss',
                'sqli',
                'csrf',
                'command-injection',
            ],
            referenceUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
        },
        '164.312(d)': {
            id: '164.312(d)',
            title: 'Person or Entity Authentication',
            description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.',
            category: 'Technical Safeguards',
            checks: [
                'auth-bypass',
                'credential-exposure',
                'weak-authentication',
            ],
            referenceUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
        },
        '164.312(e)': {
            id: '164.312(e)',
            title: 'Transmission Security',
            description: 'Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted.',
            category: 'Technical Safeguards',
            checks: [
                'missing-hsts',
                'insecure-cookie',
                'mixed-content',
                'weak-tls',
            ],
            referenceUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
        },
    },
};

/**
 * All supported frameworks
 */
export const complianceFrameworks = {
    soc2: soc2Framework,
    gdpr: gdprFramework,
    hipaa: hipaaFramework,
};

/**
 * Reverse mapping: finding type → frameworks/controls
 * This allows quick lookup of which controls are affected by a finding
 */
export const findingToControlMap: FindingToControlMapping[] = [
    {
        findingType: 'auth-bypass',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.1'] },
            { framework: 'gdpr', controls: ['Art32'] },
            { framework: 'hipaa', controls: ['164.312(a)', '164.312(d)'] },
        ],
    },
    {
        findingType: 'idor',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.1'] },
            { framework: 'hipaa', controls: ['164.312(a)'] },
        ],
    },
    {
        findingType: 'xss',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.6'] },
            { framework: 'gdpr', controls: ['Art32'] },
            { framework: 'hipaa', controls: ['164.312(c)'] },
        ],
    },
    {
        findingType: 'sqli',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.6'] },
            { framework: 'gdpr', controls: ['Art32'] },
            { framework: 'hipaa', controls: ['164.312(c)'] },
        ],
    },
    {
        findingType: 'csrf',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.1'] },
            { framework: 'hipaa', controls: ['164.312(c)'] },
        ],
    },
    {
        findingType: 'pii-exposure',
        frameworks: [
            { framework: 'gdpr', controls: ['Art5', 'Art25', 'Art32', 'Art33'] },
        ],
    },
    {
        findingType: 'secrets-leak',
        frameworks: [
            { framework: 'gdpr', controls: ['Art25', 'Art32'] },
        ],
    },
    {
        findingType: 'vulnerable-library',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.6'] },
        ],
    },
    {
        findingType: 'missing-hsts',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.7'] },
            { framework: 'gdpr', controls: ['Art32'] },
            { framework: 'hipaa', controls: ['164.312(e)'] },
        ],
    },
    {
        findingType: 'insecure-cookie',
        frameworks: [
            { framework: 'soc2', controls: ['CC6.7'] },
            { framework: 'gdpr', controls: ['Art32'] },
            { framework: 'hipaa', controls: ['164.312(e)'] },
        ],
    },
];

/**
 * Get all controls affected by a finding type
 */
export function getControlsForFinding(findingType: string): { framework: string; controlId: string }[] {
    const mapping = findingToControlMap.find((m) => m.findingType === findingType);
    if (!mapping) return [];

    const results: { framework: string; controlId: string }[] = [];
    for (const fw of mapping.frameworks) {
        for (const controlId of fw.controls) {
            results.push({ framework: fw.framework, controlId });
        }
    }
    return results;
}

/**
 * Get all finding types that map to a specific control
 */
export function getFindingsForControl(framework: string, controlId: string): string[] {
    return findingToControlMap
        .filter((m) => m.frameworks.some((fw) => fw.framework === framework && fw.controls.includes(controlId)))
        .map((m) => m.findingType);
}
