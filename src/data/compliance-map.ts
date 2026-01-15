/**
 * Regulatory Compliance Mapping
 * Maps technical rule IDs (Axe, ZAP, Lighthouse, Custom) to Compliance Standards.
 */

export const COMPLIANCE_MAP: Record<string, string[]> = {
    // Accessibility (Axe-core)
    'color-contrast': ['WCAG 2.1 AA', 'ADA Title III', 'Section 508'],
    'image-alt': ['WCAG 2.1 A', 'ADA Title III', 'Section 508'],
    'link-name': ['WCAG 2.1 A', 'ADA Title III'],
    'button-name': ['WCAG 2.1 A', 'ADA Title III'],
    'label': ['WCAG 2.1 A', 'Section 508'],
    'heading-order': ['WCAG 2.1 AA'],
    'landmark-one-main': ['WCAG 2.1 AA'],
    'aria-roles': ['WCAG 2.1 A'],

    // Security (ZAP & Custom)
    'xss-injection': ['PCI-DSS 6.5.7', 'NIST SI-10', 'SOC2 CC6.6', 'OWASP Top 10'],
    'sql-injection': ['PCI-DSS 6.5.1', 'NIST SI-10', 'SOC2 CC6.6', 'OWASP Top 10'],
    'csrf': ['PCI-DSS 6.5.9', 'OWASP Top 10', 'SOC2 CC6.6'],
    'missing-headers': ['PCI-DSS 6.5.10', 'SOC2 CC6.6', 'NIST SC-8'],
    'csp-header': ['PCI-DSS 6.5.10', 'SOC2 CC6.6'],
    'strict-transport-security': ['PCI-DSS 4.1', 'NIST SC-8', 'SOC2 CC6.7'],
    'content-type-options': ['SOC2 CC6.6'],
    'cookie-secure': ['GDPR Art 32', 'HIPAA 164.312', 'PCI-DSS 8.2.1', 'SOC2 CC6.7'],
    'cookie-http-only': ['PCI-DSS 6.5.10', 'SOC2 CC6.6'],
    'sensitive-data-exposure': ['GDPR Art 32', 'CCPA', 'HIPAA 164.312', 'PCI-DSS 3.4', 'SOC2 CC6.1'],
    'leaked-secrets': ['SOC2 CC6.1', 'PCI-DSS 2.3', 'NIST IA-2'],

    // Infrastructure / Config
    'vulnerable-library': ['PCI-DSS 6.2', 'SOC2 CC7.1', 'NIST SI-2'],
    'outdated-component': ['PCI-DSS 6.2', 'SOC2 CC7.1'],
    'open-ports': ['PCI-DSS 1.3', 'NIST CM-7', 'SOC2 CC6.6'],

    // Performance / Best Practices (Indirectly related to availability)
    'performance-budget': ['SOC2 CC2.1 (Availability)'],
    'cumulative-layout-shift': ['SOC2 CC2.1 (Availability)'],
};

/**
 * Helper to get compliance tags for a given rule ID
 * Searches for exact matches or partial matches (e.g. 'xss' matching 'xss-injection')
 */
export function getComplianceTags(ruleId: string): string[] {
    // 1. Exact match
    if (COMPLIANCE_MAP[ruleId]) {
        return COMPLIANCE_MAP[ruleId];
    }

    // 2. Partial key match (fallback)
    // finding 'xss' might map to 'xss-injection' rules
    const lowerId = ruleId.toLowerCase();
    for (const [key, tags] of Object.entries(COMPLIANCE_MAP)) {
        if (lowerId.includes(key) || key.includes(lowerId)) {
            return tags;
        }
    }

    return [];
}
