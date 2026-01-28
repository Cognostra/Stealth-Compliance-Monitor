/**
 * Policy Generator Command
 * Generates policy template files based on security profiles
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export type PolicyProfile = 'strict' | 'standard' | 'minimal';

/**
 * Policy templates for each profile
 */
const policyTemplates: Record<PolicyProfile, string> = {
    strict: `# Strict Security Policy
# Fails on any critical or high severity findings
# Use for production environments with strict compliance requirements

version: "1.0"
name: strict-security

policies:
  # Block critical vulnerabilities
  - name: "No Critical Vulnerabilities"
    condition: "severity == 'critical'"
    action: fail
    message: "Critical vulnerability found - blocking deployment"

  # Block high severity issues
  - name: "No High Severity Issues"
    condition: "severity == 'high'"
    action: fail
    message: "High severity issue found - requires immediate fix"

  # Warn on medium severity
  - name: "Medium Severity Warning"
    condition: "severity == 'medium'"
    action: warn
    message: "Medium severity issue found - should be addressed"

  # Performance budget enforcement
  - name: "Performance Budget"
    condition: "lighthouse_performance < 70"
    action: fail
    message: "Performance score below 70 - optimize before deploying"

  # Accessibility compliance
  - name: "Accessibility Minimum"
    condition: "lighthouse_accessibility < 80"
    action: fail
    message: "Accessibility score must be at least 80"

  # Security header requirements
  - name: "HSTS Required"
    condition: "type == 'missing-hsts'"
    action: fail
    message: "HSTS header is required for production"

  # XSS protection
  - name: "No XSS Vulnerabilities"
    condition: "type == 'xss'"
    action: fail
    message: "Cross-site scripting vulnerability detected"

  # SQL Injection protection
  - name: "No SQL Injection"
    condition: "type == 'sqli'"
    action: fail
    message: "SQL injection vulnerability detected"
`,

    standard: `# Standard Security Policy
# Balanced approach for CI/CD pipelines
# Blocks critical issues, warns on high severity

version: "1.0"
name: standard-security

policies:
  # Block critical only
  - name: "No Critical Vulnerabilities"
    condition: "severity == 'critical'"
    action: fail
    message: "Critical vulnerability blocks deployment"

  # Warn on high severity
  - name: "High Severity Warning"
    condition: "severity == 'high'"
    action: warn
    message: "High severity issue should be addressed soon"

  # Performance budget (more lenient)
  - name: "Performance Minimum"
    condition: "lighthouse_performance < 50"
    action: fail
    message: "Performance score critically low"

  # Accessibility baseline
  - name: "Accessibility Baseline"
    condition: "lighthouse_accessibility < 70"
    action: warn
    message: "Accessibility score below recommended threshold"

  # XSS protection
  - name: "No XSS Vulnerabilities"
    condition: "type == 'xss'"
    action: fail
    message: "Cross-site scripting vulnerability detected"
`,

    minimal: `# Minimal Security Policy
# Only blocks the most severe issues
# Suitable for development environments

version: "1.0"
name: minimal-security

policies:
  # Only block critical
  - name: "No Critical Vulnerabilities"
    condition: "severity == 'critical'"
    action: fail
    message: "Critical vulnerability detected"

  # XSS - always block
  - name: "No XSS"
    condition: "type == 'xss'"
    action: fail
    message: "XSS vulnerability must be fixed"
`,
};

export interface GeneratePolicyOptions {
    profile: PolicyProfile;
    outputPath?: string;
    overwrite?: boolean;
}

/**
 * Generate a policy file from a template
 */
export function generatePolicy(options: GeneratePolicyOptions): {
    success: boolean;
    path: string;
    message: string;
} {
    const { profile, outputPath, overwrite = false } = options;

    // Validate profile
    if (!policyTemplates[profile]) {
        return {
            success: false,
            path: '',
            message: `Invalid profile: ${profile}. Valid options: strict, standard, minimal`,
        };
    }

    // Determine output path
    const targetPath = outputPath || `.compliance-policy.yml`;
    const absolutePath = path.isAbsolute(targetPath) 
        ? targetPath 
        : path.resolve(process.cwd(), targetPath);

    // Check if file exists
    if (fs.existsSync(absolutePath) && !overwrite) {
        return {
            success: false,
            path: absolutePath,
            message: `File already exists: ${absolutePath}. Use --overwrite to replace.`,
        };
    }

    // Write the policy file
    try {
        const template = policyTemplates[profile];
        fs.writeFileSync(absolutePath, template, 'utf-8');
        
        return {
            success: true,
            path: absolutePath,
            message: `Generated ${profile} policy: ${absolutePath}`,
        };
    } catch (error) {
        return {
            success: false,
            path: absolutePath,
            message: `Failed to write policy file: ${error instanceof Error ? error.message : String(error)}`,
        };
    }
}

/**
 * Parse generate-policy CLI argument
 */
export function parseGeneratePolicyArgs(args: string[]): GeneratePolicyOptions | null {
    const generateArg = args.find(arg => 
        arg.startsWith('--generate-policy=') || arg === '--generate-policy'
    );

    if (!generateArg) {
        return null;
    }

    // Default profile
    let profile: PolicyProfile = 'standard';

    if (generateArg.includes('=')) {
        const value = generateArg.split('=')[1];
        if (value === 'strict' || value === 'standard' || value === 'minimal') {
            profile = value;
        }
    }

    // Check for output path
    const outputArg = args.find(arg => arg.startsWith('--policy-output='));
    const outputPath = outputArg ? outputArg.split('=')[1] : undefined;

    // Check for overwrite flag
    const overwrite = args.includes('--overwrite');

    return { profile, outputPath, overwrite };
}

/**
 * List available policy profiles
 */
export function listProfiles(): string[] {
    return Object.keys(policyTemplates) as PolicyProfile[];
}

/**
 * Get policy template content
 */
export function getTemplate(profile: PolicyProfile): string | undefined {
    return policyTemplates[profile];
}
