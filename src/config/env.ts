/**
 * Environment Configuration Manager
 * Loads and validates required environment variables with strict error handling
 */

import * as dotenv from 'dotenv';
import * as path from 'path';

// Load .env file from project root
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

/**
 * Application configuration interface
 */
export interface EnvConfig {
    /** Target live website URL - REQUIRED */
    LIVE_URL: string;
    /** Test user email for authentication flows - REQUIRED */
    TEST_EMAIL: string;
    /** Test user password for authentication flows - REQUIRED */
    TEST_PASSWORD: string;
    /** OWASP ZAP proxy URL for passive security scanning */
    ZAP_PROXY_URL: string;
    /** Minimum delay between actions (ms) */
    MIN_DELAY_MS: number;
    /** Maximum delay between actions (ms) */
    MAX_DELAY_MS: number;
    /** Directory for screenshots */
    SCREENSHOTS_DIR: string;
    /** Directory for reports */
    REPORTS_DIR: string;
    /** Custom User-Agent string */
    USER_AGENT: string;
    /** Crawler concurrency (parallel pages) */
    CRAWLER_CONCURRENCY: number;
    /** Maximum pages to crawl */
    CRAWLER_MAX_PAGES: number;
    /** OpenAI API Key for AI Remediation */
    OPENAI_API_KEY: string;
    /** Enable AI Remediation */
    ENABLE_AI: boolean;
    /** Auth Token Value for Direct Injection */
    AUTH_TOKEN_VALUE?: string;
    /** Auth Cookie Name for Direct Injection */
    AUTH_COOKIE_NAME?: string;
    /** Universal Webhook URL */
    WEBHOOK_URL?: string;
    /** Webhook HMAC Secret */
    WEBHOOK_SECRET?: string;
    /** Webhook Event Filter */
    WEBHOOK_EVENTS?: string;
    /** SIEM Integration Enabled */
    SIEM_ENABLED?: boolean;
    /** SIEM Webhook/HEC URL */
    SIEM_WEBHOOK_URL?: string;
    /** SIEM Log File Path */
    SIEM_LOG_PATH?: string;
}

/**
 * Get a required environment variable or throw a hard error
 * @param key - Environment variable name
 * @returns The value of the environment variable
 * @throws Error if the variable is missing or empty
 */
function getRequired(key: string): string {
    const value = process.env[key];

    if (value === undefined || value === null || value.trim() === '') {
        throw new Error(
            `[CONFIG ERROR] Missing required environment variable: ${key}\n` +
            `Please ensure ${key} is set in your .env file or environment.\n` +
            `Application cannot start without this configuration.`
        );
    }

    return value.trim();
}

/**
 * Get an optional environment variable with a default value
 * @param key - Environment variable name
 * @param defaultValue - Default value if not set
 * @returns The value or default
 */
function getOptional(key: string, defaultValue: string): string {
    const value = process.env[key];
    return (value !== undefined && value !== null && value.trim() !== '')
        ? value.trim()
        : defaultValue;
}

/**
 * Get a numeric environment variable
 * @param key - Environment variable name
 * @param defaultValue - Default numeric value
 * @returns The parsed number
 * @throws Error if value is not a valid number
 */
function getNumber(key: string, defaultValue: number): number {
    const value = process.env[key];

    if (value === undefined || value === null || value.trim() === '') {
        return defaultValue;
    }

    const parsed = parseInt(value.trim(), 10);

    if (isNaN(parsed)) {
        throw new Error(
            `[CONFIG ERROR] Invalid numeric value for ${key}: "${value}"\n` +
            `Expected a valid integer.`
        );
    }

    return parsed;
}

/**
 * Validate URL format
 * @param url - URL string to validate
 * @param key - Environment variable name for error messages
 * @throws Error if URL is invalid
 */
function validateUrl(url: string, key: string): void {
    try {
        new URL(url);
    } catch {
        throw new Error(
            `[CONFIG ERROR] Invalid URL format for ${key}: "${url}"\n` +
            `Please provide a valid URL (e.g., https://example.com)`
        );
    }
}

/**
 * Load and validate all environment configuration
 * This function throws hard errors if required variables are missing
 * @returns Validated configuration object
 * @throws Error if any required configuration is missing or invalid
 */
export function loadEnvConfig(): EnvConfig {
    console.log('[CONFIG] Loading environment configuration...');

    // Load required variables (will throw if missing)
    const LIVE_URL = getRequired('LIVE_URL');
    const TEST_EMAIL = getRequired('TEST_EMAIL');
    const TEST_PASSWORD = getRequired('TEST_PASSWORD');

    // Validate LIVE_URL format
    validateUrl(LIVE_URL, 'LIVE_URL');

    // Load optional variables with defaults
    const ZAP_PROXY_URL = getOptional('ZAP_PROXY_URL', 'http://localhost:8080');

    // Validate ZAP_PROXY_URL format if provided
    validateUrl(ZAP_PROXY_URL, 'ZAP_PROXY_URL');

    const config: EnvConfig = {
        LIVE_URL,
        TEST_EMAIL,
        TEST_PASSWORD,
        ZAP_PROXY_URL,
        MIN_DELAY_MS: getNumber('MIN_DELAY_MS', 2000),
        MAX_DELAY_MS: getNumber('MAX_DELAY_MS', 5000),
        SCREENSHOTS_DIR: getOptional('SCREENSHOTS_DIR', './screenshots'),
        REPORTS_DIR: getOptional('REPORTS_DIR', './reports'),
        USER_AGENT: getOptional(
            'USER_AGENT',
            'LSCM-Bot/1.0 (Live Site Compliance Monitor; Read-Only)'
        ),
        CRAWLER_CONCURRENCY: getNumber('CRAWLER_CONCURRENCY', 3),
        CRAWLER_MAX_PAGES: getNumber('CRAWLER_MAX_PAGES', 15),
        OPENAI_API_KEY: getOptional('OPENAI_API_KEY', ''),
        ENABLE_AI: getOptional('ENABLE_AI', 'false').toLowerCase() === 'true',
        AUTH_TOKEN_VALUE: getOptional('AUTH_TOKEN_VALUE', ''),
        AUTH_COOKIE_NAME: getOptional('AUTH_COOKIE_NAME', 'session_token'),
        WEBHOOK_URL: getOptional('WEBHOOK_URL', ''),
        WEBHOOK_SECRET: getOptional('WEBHOOK_SECRET', ''),
        WEBHOOK_EVENTS: getOptional('WEBHOOK_EVENTS', 'critical'),
        SIEM_ENABLED: getOptional('SIEM_ENABLED', 'false').toLowerCase() === 'true',
        SIEM_WEBHOOK_URL: getOptional('SIEM_WEBHOOK_URL', ''),
        SIEM_LOG_PATH: getOptional('SIEM_LOG_PATH', 'logs/security-events.log'),
    };

    // Validate delay configuration
    if (config.MIN_DELAY_MS < 1000) {
        console.warn(
            `[CONFIG WARNING] MIN_DELAY_MS (${config.MIN_DELAY_MS}ms) is below 1000ms.\n` +
            `This may trigger WAF rate limiting on the target site.`
        );
    }

    if (config.MAX_DELAY_MS < config.MIN_DELAY_MS) {
        throw new Error(
            `[CONFIG ERROR] MAX_DELAY_MS (${config.MAX_DELAY_MS}) must be >= MIN_DELAY_MS (${config.MIN_DELAY_MS})`
        );
    }

    console.log('[CONFIG] Configuration loaded successfully');
    console.log(`[CONFIG] Target: ${config.LIVE_URL}`);
    console.log(`[CONFIG] ZAP Proxy: ${config.ZAP_PROXY_URL}`);

    return config;
}

/**
 * Singleton configuration instance
 * Loads configuration on first access
 */
let configInstance: EnvConfig | null = null;

/**
 * Get the configuration singleton
 * @returns The validated configuration object
 * @throws Error if configuration is invalid
 */
export function getConfig(): EnvConfig {
    if (!configInstance) {
        configInstance = loadEnvConfig();
    }
    return configInstance;
}

/**
 * Reset configuration (for testing purposes)
 */
export function resetConfig(): void {
    configInstance = null;
}

export default getConfig;
