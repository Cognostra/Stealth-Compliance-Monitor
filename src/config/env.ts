/**
 * Environment Configuration Manager
 * Loads and validates required environment variables with strict error handling
 */

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { initDeterministic } from '../utils/random.js';

function findProjectRoot(startDir: string): string {
    let dir = startDir;
    for (let i = 0; i < 6; i++) {
        if (fs.existsSync(path.join(dir, 'package.json'))) {
            return dir;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    return process.cwd();
}

// Load .env file from project root (prefer repo root over cwd)
const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = findProjectRoot(moduleDir);
const rootEnvPath = path.join(projectRoot, '.env');
const cwdEnvPath = path.resolve(process.cwd(), '.env');

if (fs.existsSync(rootEnvPath)) {
    dotenv.config({ path: rootEnvPath });
} else if (fs.existsSync(cwdEnvPath)) {
    dotenv.config({ path: cwdEnvPath });
}

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
    /** ZAP API Key for secure access (optional, disabled by default for dev) */
    ZAP_API_KEY?: string;
    /** Enable Custom Compliance Checks */
    CUSTOM_CHECKS_ENABLED: boolean;
    /** Directory for Custom Check Scripts */
    CUSTOM_CHECKS_DIR: string;
    /** Devices to emulate (e.g. ['desktop', 'iPhone 14']) */
    DEVICES: string[];
    /** Enable API Endpoint Testing */
    API_TESTING_ENABLED: boolean;
    /** Path to OpenAPI/Swagger spec file or URL */
    API_SPEC_PATH?: string;
    /** Additional API endpoints to test (comma-separated) */
    API_ENDPOINTS?: string;
    
    // Debug Mode Options
    /** Run browser in headed mode (visible) */
    DEBUG_HEADED: boolean;
    /** Slow down actions by this many ms (for debugging) */
    DEBUG_SLOW_MO: number;
    /** Enable devtools on launch */
    DEBUG_DEVTOOLS: boolean;
    /** Pause on failures for debugging */
    DEBUG_PAUSE_ON_FAILURE: boolean;
    /** Capture console logs on errors */
    DEBUG_CAPTURE_CONSOLE: boolean;
    
    // Vulnerability Intelligence Options
    /** Enable vulnerability intelligence enrichment */
    VULN_INTEL_ENABLED: boolean;
    /** NVD API key for higher rate limits (optional) */
    NVD_API_KEY?: string;
    /** Enable exploit database cross-referencing */
    VULN_INTEL_EXPLOITS: boolean;
    /** Enable CISA KEV catalog checking */
    VULN_INTEL_KEV: boolean;
    /** Enable CWE description enrichment */
    VULN_INTEL_CWE: boolean;
    /** Cache vulnerability data (minutes, default 1440 = 24h) */
    VULN_INTEL_CACHE_TTL: number;
    /** Path to vulnerability intelligence cache file */
    VULN_INTEL_CACHE_PATH: string;
    
    // Report Branding Options
    /** Custom company/organization name for reports */
    BRAND_COMPANY_NAME: string;
    /** URL to custom logo image (PNG/SVG recommended, max 200x50px) */
    BRAND_LOGO_URL?: string;
    /** Primary brand color (hex, e.g., #3fb950) */
    BRAND_PRIMARY_COLOR: string;
    /** URL to external CSS file for advanced customization */
    BRAND_CUSTOM_CSS_URL?: string;
    /** Custom footer text for reports */
    BRAND_FOOTER_TEXT?: string;
    /** Report title prefix (appears before "Compliance Report") */
    BRAND_REPORT_TITLE?: string;
    /** Enable deterministic mode (stable randomness) */
    DETERMINISTIC_MODE: boolean;
    /** Seed for deterministic mode */
    DETERMINISTIC_SEED: number;
    /** Allow active ZAP scanning */
    ACTIVE_SCAN_ALLOWED: boolean;
    /** Allowlist of targets for active scanning */
    ACTIVE_SCAN_ALLOWLIST: string[];
    /** Visual regression diff threshold (0-1) */
    VISUAL_DIFF_THRESHOLD: number;
    /** Baseline max age (days) before approval required */
    VISUAL_BASELINE_MAX_AGE_DAYS: number;
    /** Auto-approve baseline refresh when expired */
    VISUAL_BASELINE_AUTO_APPROVE: boolean;
    /** Enable log redaction */
    REDACTION_ENABLED: boolean;
    /** Optional run tag for reports/logs */
    RUN_TAG?: string;
    /** Cron schedule for continuous monitoring */
    CRON_SCHEDULE?: string;
    /** Allowed directories for policy files (comma-separated, prevents path traversal) */
    POLICY_ALLOWED_DIRS: string[];

    // Ollama / Local LLM Options
    /** Ollama API base URL */
    OLLAMA_URL: string;
    /** Default Ollama model for remediation */
    OLLAMA_MODEL: string;
    /** AI provider selection: 'openai' or 'ollama' */
    AI_PROVIDER: string;

    // Flutter Semantics Options
    /** Enable Flutter web semantics accessibility scanning */
    FLUTTER_SEMANTICS_ENABLED: boolean;

    // Python Plugin Bridge Options
    /** Enable Python custom checks */
    PYTHON_CHECKS_ENABLED: boolean;
    /** Python executable path */
    PYTHON_EXECUTABLE: string;
    /** Python check timeout (ms) */
    PYTHON_CHECK_TIMEOUT: number;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 1: Core Security
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable SBOM (Software Bill of Materials) scanning */
    SBOM_SCANNER_ENABLED: boolean;
    /** Enable GraphQL deep security scanning */
    GRAPHQL_SCANNER_ENABLED: boolean;
    /** Enable WebSocket security auditing */
    WEBSOCKET_AUDITOR_ENABLED: boolean;
    /** Enable CSP violation collection */
    CSP_COLLECTOR_ENABLED: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 2: AI-Powered
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable Visual AI compliance checking */
    VISUAL_AI_COMPLIANCE_ENABLED: boolean;
    /** Brand color palette guide path for visual compliance */
    BRAND_GUIDE_PATH?: string;
    /** Enable browser fingerprinting detection */
    FINGERPRINT_DETECTION_ENABLED: boolean;
    /** Enable AI-generated test flow generation */
    AI_TEST_FLOW_GENERATOR_ENABLED: boolean;
    /** Enable smart false positive filtering */
    FALSE_POSITIVE_FILTER_ENABLED: boolean;
    /** False positive filter confidence threshold (0-1) */
    FP_FILTER_THRESHOLD: number;
    /** Enable privacy policy analyzer */
    PRIVACY_POLICY_ANALYZER_ENABLED: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 3: Web Platform
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable WebRTC security analysis */
    WEBRTC_ANALYZER_ENABLED: boolean;
    /** Enable PWA security scanning */
    PWA_SCANNER_ENABLED: boolean;
    /** Enable browser extension audit */
    EXTENSION_AUDIT_ENABLED: boolean;
    /** Enable mobile security scanning */
    MOBILE_SECURITY_SCANNER_ENABLED: boolean;
    /** Enable Shadow DOM & Web Components scanning */
    SHADOW_DOM_SCANNER_ENABLED: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 4: Infrastructure/DevSecOps
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable WebAssembly security scanning */
    WASM_SCANNER_ENABLED: boolean;
    /** Enable container security scanning */
    CONTAINER_SCANNER_ENABLED: boolean;
    /** Enable Kubernetes security scanning */
    K8S_SCANNER_ENABLED: boolean;
    /** Enable API contract testing */
    API_CONTRACT_TESTING_ENABLED: boolean;
    /** Enable chaos engineering tests */
    CHAOS_TESTING_ENABLED: boolean;
    /** Enable multi-region compliance testing */
    MULTI_REGION_COMPLIANCE_ENABLED: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 5: Integrations
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable VS Code extension integration */
    VSCODE_INTEGRATION_ENABLED: boolean;
    /** Enable GitHub App integration */
    GITHUB_INTEGRATION_ENABLED: boolean;
    /** GitHub App ID */
    GITHUB_APP_ID?: string;
    /** GitHub App Private Key */
    GITHUB_PRIVATE_KEY?: string;
    /** GitHub App Installation ID */
    GITHUB_INSTALLATION_ID?: string;
    /** Enable Postman/Newman integration */
    POSTMAN_INTEGRATION_ENABLED: boolean;
    /** Postman API Key */
    POSTMAN_API_KEY?: string;
    /** Enable JIRA/ServiceNow ticketing integration */
    TICKETING_INTEGRATION_ENABLED: boolean;
    /** JIRA base URL */
    JIRA_BASE_URL?: string;
    /** JIRA username */
    JIRA_USERNAME?: string;
    /** JIRA API token */
    JIRA_API_TOKEN?: string;
    /** JIRA project key */
    JIRA_PROJECT_KEY?: string;
    /** ServiceNow instance */
    SERVICENOW_INSTANCE?: string;
    /** ServiceNow username */
    SERVICENOW_USERNAME?: string;
    /** ServiceNow password */
    SERVICENOW_PASSWORD?: string;
    /** Enable Slack/Teams messaging integration */
    MESSAGING_INTEGRATION_ENABLED: boolean;
    /** Slack webhook URL */
    SLACK_WEBHOOK_URL?: string;
    /** Slack bot token */
    SLACK_BOT_TOKEN?: string;
    /** Slack channel */
    SLACK_CHANNEL?: string;
    /** Teams webhook URL */
    TEAMS_WEBHOOK_URL?: string;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 6: Enterprise
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable FAIR risk quantification */
    FAIR_RISK_QUANTIFICATION_ENABLED: boolean;
    /** Organization annual revenue (for FAIR calculations) */
    FAIR_ORGANIZATION_REVENUE?: number;
    /** Enable compliance drift detection */
    DRIFT_DETECTION_ENABLED: boolean;
    /** Enable third-party risk aggregation */
    THIRD_PARTY_RISK_ENABLED: boolean;
    /** SecurityScorecard API Key */
    SECURITYSCORECARD_API_KEY?: string;
    /** BitSight API Key */
    BITSIGHT_API_KEY?: string;
    /** Enable real-time dashboard */
    REALTIME_DASHBOARD_ENABLED: boolean;
    /** Dashboard refresh interval (ms) */
    DASHBOARD_REFRESH_INTERVAL: number;
    /** Enable evidence vault for legal hold */
    EVIDENCE_VAULT_ENABLED: boolean;
    /** Evidence vault storage path */
    EVIDENCE_VAULT_PATH: string;
    /** Evidence retention days */
    EVIDENCE_RETENTION_DAYS: number;
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
 * Get a numeric environment variable (float)
 */
function getFloat(key: string, defaultValue: number): number {
    const value = process.env[key];

    if (value === undefined || value === null || value.trim() === '') {
        return defaultValue;
    }

    const parsed = parseFloat(value.trim());

    if (isNaN(parsed)) {
        throw new Error(
            `[CONFIG ERROR] Invalid numeric value for ${key}: "${value}"\n` +
            `Expected a valid number.`
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
        ZAP_API_KEY: getOptional('ZAP_API_KEY', ''),
        CUSTOM_CHECKS_ENABLED: getOptional('CUSTOM_CHECKS_ENABLED', 'true').toLowerCase() === 'true',
        CUSTOM_CHECKS_DIR: getOptional('CUSTOM_CHECKS_DIR', './custom_checks'),
        DEVICES: getOptional('DEVICES', 'desktop').split(',').map(d => d.trim()).filter(d => d.length > 0),
        API_TESTING_ENABLED: getOptional('API_TESTING_ENABLED', 'false').toLowerCase() === 'true',
        API_SPEC_PATH: getOptional('API_SPEC_PATH', ''),
        API_ENDPOINTS: getOptional('API_ENDPOINTS', ''),
        
        // Debug Mode Options (all off by default)
        DEBUG_HEADED: getOptional('DEBUG_HEADED', 'false').toLowerCase() === 'true',
        DEBUG_SLOW_MO: getNumber('DEBUG_SLOW_MO', 0),
        DEBUG_DEVTOOLS: getOptional('DEBUG_DEVTOOLS', 'false').toLowerCase() === 'true',
        DEBUG_PAUSE_ON_FAILURE: getOptional('DEBUG_PAUSE_ON_FAILURE', 'false').toLowerCase() === 'true',
        DEBUG_CAPTURE_CONSOLE: getOptional('DEBUG_CAPTURE_CONSOLE', 'false').toLowerCase() === 'true',
        
        // Vulnerability Intelligence Options
        VULN_INTEL_ENABLED: getOptional('VULN_INTEL_ENABLED', 'true').toLowerCase() === 'true',
        NVD_API_KEY: getOptional('NVD_API_KEY', ''),
        VULN_INTEL_EXPLOITS: getOptional('VULN_INTEL_EXPLOITS', 'true').toLowerCase() === 'true',
        VULN_INTEL_KEV: getOptional('VULN_INTEL_KEV', 'true').toLowerCase() === 'true',
        VULN_INTEL_CWE: getOptional('VULN_INTEL_CWE', 'true').toLowerCase() === 'true',
        VULN_INTEL_CACHE_TTL: getNumber('VULN_INTEL_CACHE_TTL', 1440),
        VULN_INTEL_CACHE_PATH: getOptional('VULN_INTEL_CACHE_PATH', './cache/vuln-intel-cache.json'),
        
        // Report Branding Options
        BRAND_COMPANY_NAME: getOptional('BRAND_COMPANY_NAME', 'Stealth Compliance Monitor'),
        BRAND_LOGO_URL: getOptional('BRAND_LOGO_URL', ''),
        BRAND_PRIMARY_COLOR: getOptional('BRAND_PRIMARY_COLOR', '#3fb950'),
        BRAND_CUSTOM_CSS_URL: getOptional('BRAND_CUSTOM_CSS_URL', ''),
        BRAND_FOOTER_TEXT: getOptional('BRAND_FOOTER_TEXT', ''),
        BRAND_REPORT_TITLE: getOptional('BRAND_REPORT_TITLE', ''),
        DETERMINISTIC_MODE: getOptional('DETERMINISTIC_MODE', 'false').toLowerCase() === 'true',
        DETERMINISTIC_SEED: getNumber('DETERMINISTIC_SEED', 42),
        ACTIVE_SCAN_ALLOWED: getOptional('ACTIVE_SCAN_ALLOWED', 'false').toLowerCase() === 'true',
        ACTIVE_SCAN_ALLOWLIST: getOptional('ACTIVE_SCAN_ALLOWLIST', '')
            .split(',')
            .map(v => v.trim())
            .filter(v => v.length > 0),
        VISUAL_DIFF_THRESHOLD: getFloat('VISUAL_DIFF_THRESHOLD', 0.05),
        VISUAL_BASELINE_MAX_AGE_DAYS: getNumber('VISUAL_BASELINE_MAX_AGE_DAYS', 30),
        VISUAL_BASELINE_AUTO_APPROVE: getOptional('VISUAL_BASELINE_AUTO_APPROVE', 'false').toLowerCase() === 'true',
        REDACTION_ENABLED: getOptional('REDACTION_ENABLED', 'true').toLowerCase() === 'true',
        RUN_TAG: getOptional('RUN_TAG', ''),
        CRON_SCHEDULE: getOptional('CRON_SCHEDULE', ''),
        POLICY_ALLOWED_DIRS: getOptional('POLICY_ALLOWED_DIRS', './policies,.')
            .split(',')
            .map(d => d.trim())
            .filter(d => d.length > 0),

        // Ollama / Local LLM Options
        OLLAMA_URL: getOptional('OLLAMA_URL', 'http://localhost:11434'),
        OLLAMA_MODEL: getOptional('OLLAMA_MODEL', 'codellama:13b'),
        AI_PROVIDER: getOptional('AI_PROVIDER', 'openai'),

        // Flutter Semantics Options
        FLUTTER_SEMANTICS_ENABLED: getOptional('FLUTTER_SEMANTICS_ENABLED', 'false').toLowerCase() === 'true',

        // Python Plugin Bridge Options
        PYTHON_CHECKS_ENABLED: getOptional('PYTHON_CHECKS_ENABLED', 'false').toLowerCase() === 'true',
        PYTHON_EXECUTABLE: getOptional('PYTHON_EXECUTABLE', 'python3'),
        PYTHON_CHECK_TIMEOUT: getNumber('PYTHON_CHECK_TIMEOUT', 60000),

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 1: Core Security
        // ═══════════════════════════════════════════════════════════════════════════════
        SBOM_SCANNER_ENABLED: getOptional('SBOM_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        GRAPHQL_SCANNER_ENABLED: getOptional('GRAPHQL_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        WEBSOCKET_AUDITOR_ENABLED: getOptional('WEBSOCKET_AUDITOR_ENABLED', 'false').toLowerCase() === 'true',
        CSP_COLLECTOR_ENABLED: getOptional('CSP_COLLECTOR_ENABLED', 'false').toLowerCase() === 'true',

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 2: AI-Powered
        // ═══════════════════════════════════════════════════════════════════════════════
        VISUAL_AI_COMPLIANCE_ENABLED: getOptional('VISUAL_AI_COMPLIANCE_ENABLED', 'false').toLowerCase() === 'true',
        BRAND_GUIDE_PATH: getOptional('BRAND_GUIDE_PATH', ''),
        FINGERPRINT_DETECTION_ENABLED: getOptional('FINGERPRINT_DETECTION_ENABLED', 'false').toLowerCase() === 'true',
        AI_TEST_FLOW_GENERATOR_ENABLED: getOptional('AI_TEST_FLOW_GENERATOR_ENABLED', 'false').toLowerCase() === 'true',
        FALSE_POSITIVE_FILTER_ENABLED: getOptional('FALSE_POSITIVE_FILTER_ENABLED', 'false').toLowerCase() === 'true',
        FP_FILTER_THRESHOLD: getFloat('FP_FILTER_THRESHOLD', 0.3),
        PRIVACY_POLICY_ANALYZER_ENABLED: getOptional('PRIVACY_POLICY_ANALYZER_ENABLED', 'false').toLowerCase() === 'true',

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 3: Web Platform
        // ═══════════════════════════════════════════════════════════════════════════════
        WEBRTC_ANALYZER_ENABLED: getOptional('WEBRTC_ANALYZER_ENABLED', 'false').toLowerCase() === 'true',
        PWA_SCANNER_ENABLED: getOptional('PWA_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        EXTENSION_AUDIT_ENABLED: getOptional('EXTENSION_AUDIT_ENABLED', 'false').toLowerCase() === 'true',
        MOBILE_SECURITY_SCANNER_ENABLED: getOptional('MOBILE_SECURITY_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        SHADOW_DOM_SCANNER_ENABLED: getOptional('SHADOW_DOM_SCANNER_ENABLED', 'false').toLowerCase() === 'true',

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 4: Infrastructure/DevSecOps
        // ═══════════════════════════════════════════════════════════════════════════════
        WASM_SCANNER_ENABLED: getOptional('WASM_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        CONTAINER_SCANNER_ENABLED: getOptional('CONTAINER_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        K8S_SCANNER_ENABLED: getOptional('K8S_SCANNER_ENABLED', 'false').toLowerCase() === 'true',
        API_CONTRACT_TESTING_ENABLED: getOptional('API_CONTRACT_TESTING_ENABLED', 'false').toLowerCase() === 'true',
        CHAOS_TESTING_ENABLED: getOptional('CHAOS_TESTING_ENABLED', 'false').toLowerCase() === 'true',
        MULTI_REGION_COMPLIANCE_ENABLED: getOptional('MULTI_REGION_COMPLIANCE_ENABLED', 'false').toLowerCase() === 'true',

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 5: Integrations
        // ═══════════════════════════════════════════════════════════════════════════════
        VSCODE_INTEGRATION_ENABLED: getOptional('VSCODE_INTEGRATION_ENABLED', 'false').toLowerCase() === 'true',
        GITHUB_INTEGRATION_ENABLED: getOptional('GITHUB_INTEGRATION_ENABLED', 'false').toLowerCase() === 'true',
        GITHUB_APP_ID: getOptional('GITHUB_APP_ID', ''),
        GITHUB_PRIVATE_KEY: getOptional('GITHUB_PRIVATE_KEY', ''),
        GITHUB_INSTALLATION_ID: getOptional('GITHUB_INSTALLATION_ID', ''),
        POSTMAN_INTEGRATION_ENABLED: getOptional('POSTMAN_INTEGRATION_ENABLED', 'false').toLowerCase() === 'true',
        POSTMAN_API_KEY: getOptional('POSTMAN_API_KEY', ''),
        TICKETING_INTEGRATION_ENABLED: getOptional('TICKETING_INTEGRATION_ENABLED', 'false').toLowerCase() === 'true',
        JIRA_BASE_URL: getOptional('JIRA_BASE_URL', ''),
        JIRA_USERNAME: getOptional('JIRA_USERNAME', ''),
        JIRA_API_TOKEN: getOptional('JIRA_API_TOKEN', ''),
        JIRA_PROJECT_KEY: getOptional('JIRA_PROJECT_KEY', ''),
        SERVICENOW_INSTANCE: getOptional('SERVICENOW_INSTANCE', ''),
        SERVICENOW_USERNAME: getOptional('SERVICENOW_USERNAME', ''),
        SERVICENOW_PASSWORD: getOptional('SERVICENOW_PASSWORD', ''),
        MESSAGING_INTEGRATION_ENABLED: getOptional('MESSAGING_INTEGRATION_ENABLED', 'false').toLowerCase() === 'true',
        SLACK_WEBHOOK_URL: getOptional('SLACK_WEBHOOK_URL', ''),
        SLACK_BOT_TOKEN: getOptional('SLACK_BOT_TOKEN', ''),
        SLACK_CHANNEL: getOptional('SLACK_CHANNEL', '#security-alerts'),
        TEAMS_WEBHOOK_URL: getOptional('TEAMS_WEBHOOK_URL', ''),

        // ═══════════════════════════════════════════════════════════════════════════════
        // v3.2 FEATURE FLAGS - Phase 6: Enterprise
        // ═══════════════════════════════════════════════════════════════════════════════
        FAIR_RISK_QUANTIFICATION_ENABLED: getOptional('FAIR_RISK_QUANTIFICATION_ENABLED', 'false').toLowerCase() === 'true',
        FAIR_ORGANIZATION_REVENUE: getOptional('FAIR_ORGANIZATION_REVENUE', '') ? 
            parseInt(getOptional('FAIR_ORGANIZATION_REVENUE', '10000000'), 10) : 10000000,
        DRIFT_DETECTION_ENABLED: getOptional('DRIFT_DETECTION_ENABLED', 'false').toLowerCase() === 'true',
        THIRD_PARTY_RISK_ENABLED: getOptional('THIRD_PARTY_RISK_ENABLED', 'false').toLowerCase() === 'true',
        SECURITYSCORECARD_API_KEY: getOptional('SECURITYSCORECARD_API_KEY', ''),
        BITSIGHT_API_KEY: getOptional('BITSIGHT_API_KEY', ''),
        REALTIME_DASHBOARD_ENABLED: getOptional('REALTIME_DASHBOARD_ENABLED', 'false').toLowerCase() === 'true',
        DASHBOARD_REFRESH_INTERVAL: getNumber('DASHBOARD_REFRESH_INTERVAL', 5000),
        EVIDENCE_VAULT_ENABLED: getOptional('EVIDENCE_VAULT_ENABLED', 'false').toLowerCase() === 'true',
        EVIDENCE_VAULT_PATH: getOptional('EVIDENCE_VAULT_PATH', './evidence'),
        EVIDENCE_RETENTION_DAYS: getNumber('EVIDENCE_RETENTION_DAYS', 2555),
    };

    // Parse Performance Budget
    const minScore = getNumber('PERFORMANCE_BUDGET_MIN_SCORE', 0);
    if (minScore > 0) {
        (config as any).performanceBudget = {
            minScore,
            maxLCP: getNumber('PERFORMANCE_BUDGET_MAX_LCP', 0) || undefined,
            maxCLS: getFloat('PERFORMANCE_BUDGET_MAX_CLS', 0) || undefined,
            maxTBT: getNumber('PERFORMANCE_BUDGET_MAX_TBT', 0) || undefined,
        };
    }

    if (config.DETERMINISTIC_MODE) {
        initDeterministic(config.DETERMINISTIC_SEED);
    }

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
