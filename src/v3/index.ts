/**
 * Stealth Compliance Monitor v3
 * Entry point for v3 features with feature flags
 */

// Re-export all v3 modules
export * from './types/index.js';
export * from './core/index.js';
export * from './reporters/index.js';
export * from './compliance/index.js';
export * from './services/index.js';
export * from './commands/index.js';

// Feature flag interface
export interface V3FeatureFlags {
    /** Enable SARIF output */
    sarif: boolean;
    /** Path to SARIF output file (undefined = stdout) */
    sarifPath?: string;
    /** Enable policy evaluation */
    policy: boolean;
    /** Path to policy file */
    policyPath?: string;
    /** Enable compliance framework mapping */
    compliance: boolean;
    /** Frameworks to include */
    complianceFrameworks: string[];
}

/**
 * Default feature flags
 */
export const defaultFeatureFlags: V3FeatureFlags = {
    sarif: false,
    policy: false,
    compliance: false,
    complianceFrameworks: [],
};

/**
 * Parse v3 feature flags from CLI arguments
 */
export function parseV3Flags(args: string[]): V3FeatureFlags {
    const flags = { ...defaultFeatureFlags };

    for (const arg of args) {
        // --sarif or --sarif=path
        if (arg === '--sarif') {
            flags.sarif = true;
        } else if (arg.startsWith('--sarif=')) {
            flags.sarif = true;
            flags.sarifPath = arg.slice(8);
        }

        // --policy=path
        if (arg.startsWith('--policy=')) {
            flags.policy = true;
            flags.policyPath = arg.slice(9);
        }

        // --compliance=soc2,gdpr
        if (arg.startsWith('--compliance=')) {
            flags.compliance = true;
            flags.complianceFrameworks = arg.slice(13).split(',').map((f) => f.trim().toLowerCase());
        }
    }

    return flags;
}

/**
 * v3 version identifier
 */
export const V3_VERSION = '3.0.0-alpha.1';
