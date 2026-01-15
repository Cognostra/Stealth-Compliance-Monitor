import { getConfig, EnvConfig } from './env';

/**
 * Runtime configuration schema
 */
export interface RuntimeProfile {
    maxPages: number;
    concurrency: number;
    activeSecurity: boolean;
    name: string;
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

export const PROFILES: Record<string, RuntimeProfile> = {
    'smoke': {
        name: 'Smoke',
        maxPages: 1,
        concurrency: 1,
        activeSecurity: false,
    },
    'standard': {
        name: 'Standard',
        maxPages: 15,
        concurrency: 3,
        activeSecurity: false,
    },
    'deep': {
        name: 'Deep',
        maxPages: 50,
        concurrency: 5,
        activeSecurity: true,
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
    if (env.AUTH_TOKEN_VALUE && env.AUTH_TOKEN_VALUE.length > 0) {
        config.authBypass = {
            cookieName: env.AUTH_COOKIE_NAME || 'session_token',
            tokenValue: env.AUTH_TOKEN_VALUE,
            domain: mainDomain
        };
    }

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
