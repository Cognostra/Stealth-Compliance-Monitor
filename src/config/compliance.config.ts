import { getConfig, EnvConfig } from './env.js';

/**
 * Runtime configuration schema
 */
export interface RuntimeProfile {
    /** Profile display name */
    name: string;
    /** Maximum pages to crawl */
    maxPages: number;
    /** Concurrent page crawling */
    concurrency: number;
    /** Enable black-box security testing (IDOR, XSS probes) */
    activeSecurity: boolean;
    /** 
     * Enable ZAP active scanning (spider + active scan)
     * WARNING: This is aggressive and may trigger WAF/IDS
     * Only use with explicit permission on owned systems
     */
    activeScanning: boolean;
}

/**
 * Full Merged Configuration (Env + Runtime)
 */
export type ComplianceConfig = EnvConfig & RuntimeProfile & {
    targetUrl: string | string[];
    authBypass?: {
        cookieName: string;
        tokenValue: string;
        domain: string;
    };
    webhook?: WebhookConfig;
    siem?: SiemConfig;
    stealth?: boolean;

    // Custom Checks
    enableCustomChecks?: boolean;
    customChecksDir?: string;

    // API Testing
    enableApiTesting?: boolean;
    apiSpecPath?: string;
    apiEndpoints?: string[];

    // Vulnerability Intelligence
    enableVulnIntel?: boolean;
    nvdApiKey?: string;
    vulnIntelExploits?: boolean;
    vulnIntelKev?: boolean;
    vulnIntelCwe?: boolean;
    vulnIntelCacheTtl?: number;
    vulnIntelCachePath?: string;
    // Active scan guardrails
    activeScanAllowed?: boolean;
    activeScanAllowlist?: string[];

    // Deterministic mode
    deterministicMode?: boolean;
    deterministicSeed?: number;

    // Visual regression policy
    visualDiffThreshold?: number;
    visualBaselineMaxAgeDays?: number;
    visualBaselineAutoApprove?: boolean;

    // Redaction
    redactionEnabled?: boolean;
    runTag?: string;
};

export interface WebhookConfig {
    url: string;
    secret?: string;
    events: 'critical' | 'all';
}

export interface SiemConfig {
    enabled: boolean;
    webhookUrl?: string;
    logFilePath?: string;
}


/**
 * Predefined scan profiles
 * 
 * - smoke: Quick health check (1 page, no security tests)
 * - standard: Regular CI/CD scans (15 pages, passive security)
 * - deep: Full passive assessment (50 pages, black-box probes)
 * - deep-active: Full active assessment (50 pages, ZAP spider + active scan)
 */
export const PROFILES: Record<string, RuntimeProfile> = {
    'smoke': {
        name: 'Smoke',
        maxPages: 1,
        concurrency: 1,
        activeSecurity: false,
        activeScanning: false,
    },
    'standard': {
        name: 'Standard',
        maxPages: 15,
        concurrency: 3,
        activeSecurity: false,
        activeScanning: false,
    },
    'deep': {
        name: 'Deep',
        maxPages: 50,
        concurrency: 5,
        activeSecurity: true,
        activeScanning: false,
    },
    'deep-active': {
        name: 'Deep Active',
        maxPages: 50,
        concurrency: 3, // Lower concurrency for active scanning
        activeSecurity: true,
        activeScanning: true,
    }
};

export const DEFAULT_PROFILE = 'standard';


/**
 * Helper to merge environment config with profile
 */
export function createConfig(profileName: string = DEFAULT_PROFILE): ComplianceConfig {
    const env = getConfig();
    const profile = PROFILES[profileName.toLowerCase()] || PROFILES[DEFAULT_PROFILE];

    // Determine Target(s)
    let targetUrl: string | string[] = env.LIVE_URL;
    let mainDomain = 'localhost';

    // Check if LIVE_URL is a path to a JSON file
    if (env.LIVE_URL.endsWith('.json')) {
        // We will resolve this content later or just pass the path?
        // Ideally we resolve it here if we can import fs
        // But createConfig might be used where fs isn't available? No, this is node.
        // Let's assume index.ts handles the file reading if it's a file, or we do it here.
        // Actually, let's keep it simple: if it contains commas, it's a list. 
        // If it starts with file://, it's a file.
        // If it ends with .json, let's treat it as a file path config.
    } else if (env.LIVE_URL.includes(',')) {
        targetUrl = env.LIVE_URL.split(',').map(u => u.trim());
    }

    // Extract domain from first target for initial cookie scoping
    try {
        const firstUrl = Array.isArray(targetUrl) ? targetUrl[0] : targetUrl;
        if (firstUrl.startsWith('http')) {
            const url = new URL(firstUrl);
            mainDomain = url.hostname;
        }
    } catch (e) {
        // Fallback
    }

    const config: ComplianceConfig = {
        ...env,
        ...profile,
        targetUrl,
        stealth: true // Default to true
    };

    // Configure Auth Bypass if token is provided
    // Configure Auth Bypass if token is provided
    if (env.AUTH_TOKEN_VALUE && env.AUTH_TOKEN_VALUE.length > 0) {
        config.authBypass = {
            cookieName: env.AUTH_COOKIE_NAME || 'session_token',
            tokenValue: env.AUTH_TOKEN_VALUE,
            domain: mainDomain
        };
    }

    // Configure Custom Checks
    config.enableCustomChecks = env.CUSTOM_CHECKS_ENABLED;
    config.customChecksDir = env.CUSTOM_CHECKS_DIR;

    // Configure API Testing
    config.enableApiTesting = env.API_TESTING_ENABLED;
    config.apiSpecPath = env.API_SPEC_PATH;
    if (env.API_ENDPOINTS && env.API_ENDPOINTS.length > 0) {
        config.apiEndpoints = env.API_ENDPOINTS.split(',').map(e => e.trim()).filter(e => e.length > 0);
    }

    // Configure Vulnerability Intelligence
    config.enableVulnIntel = env.VULN_INTEL_ENABLED;
    config.nvdApiKey = env.NVD_API_KEY;
    config.vulnIntelExploits = env.VULN_INTEL_EXPLOITS;
    config.vulnIntelKev = env.VULN_INTEL_KEV;
    config.vulnIntelCwe = env.VULN_INTEL_CWE;
    config.vulnIntelCacheTtl = env.VULN_INTEL_CACHE_TTL;
    config.vulnIntelCachePath = env.VULN_INTEL_CACHE_PATH;

    // Active scan guardrails
    config.activeScanAllowed = env.ACTIVE_SCAN_ALLOWED;
    config.activeScanAllowlist = env.ACTIVE_SCAN_ALLOWLIST;

    // Deterministic mode
    config.deterministicMode = env.DETERMINISTIC_MODE;
    config.deterministicSeed = env.DETERMINISTIC_SEED;

    // Visual regression policy
    config.visualDiffThreshold = env.VISUAL_DIFF_THRESHOLD;
    config.visualBaselineMaxAgeDays = env.VISUAL_BASELINE_MAX_AGE_DAYS;
    config.visualBaselineAutoApprove = env.VISUAL_BASELINE_AUTO_APPROVE;

    // Redaction
    config.redactionEnabled = env.REDACTION_ENABLED;
    config.runTag = env.RUN_TAG;

    // Configure Webhook
    if (env.WEBHOOK_URL && env.WEBHOOK_URL.length > 0) {
        config.webhook = {
            url: env.WEBHOOK_URL,
            secret: env.WEBHOOK_SECRET,
            events: (env.WEBHOOK_EVENTS === 'all') ? 'all' : 'critical'
        };
    }

    // Configure SIEM
    config.siem = {
        enabled: env.SIEM_ENABLED || false,
        webhookUrl: env.SIEM_WEBHOOK_URL,
        logFilePath: env.SIEM_LOG_PATH
    };

    return config;
}
