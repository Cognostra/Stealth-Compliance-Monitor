/**
 * V3 Constants and Configuration Limits
 *
 * Centralized constants to eliminate magic numbers and improve maintainability.
 * All limits are designed for security and resource management.
 */

/**
 * Security and Validation Limits
 */
export const LIMITS = {
    /** Maximum YAML file size in bytes (1MB) */
    YAML_MAX_SIZE_BYTES: 1 * 1024 * 1024,

    /** Maximum JSON file size in bytes (10MB) */
    JSON_MAX_SIZE_BYTES: 10 * 1024 * 1024,

    /** Maximum regex pattern length */
    REGEX_MAX_LENGTH: 200,

    /** Maximum YAML alias count (billion laughs protection) */
    YAML_MAX_ALIASES: 50,

    /** Maximum policies per configuration file */
    MAX_POLICIES_PER_FILE: 100,

    /** Maximum trend records per target URL */
    TREND_MAX_RECORDS_PER_TARGET: 50,

    /** Maximum file path length */
    MAX_FILE_PATH_LENGTH: 4096,
} as const;

/**
 * Timeout Configuration
 */
export const TIMEOUTS = {
    /** Regex execution timeout in milliseconds */
    REGEX_TIMEOUT_MS: 100,

    /** File I/O operation timeout in milliseconds */
    FILE_IO_TIMEOUT_MS: 5000,

    /** Policy evaluation timeout in milliseconds */
    POLICY_EVAL_TIMEOUT_MS: 10000,
} as const;

/**
 * Cleanup and Retention Thresholds
 */
export const RETENTION = {
    /** Maximum age for trend history in days */
    TREND_MAX_AGE_DAYS: 90,

    /** Cleanup interval in milliseconds (24 hours) */
    CLEANUP_INTERVAL_MS: 24 * 60 * 60 * 1000,
} as const;

/**
 * Circuit Breaker Configuration
 */
export const CIRCUIT_BREAKER = {
    /** Maximum consecutive failures before opening circuit */
    MAX_FAILURES: 5,

    /** Consecutive successes needed to close circuit */
    RESET_THRESHOLD: 3,
} as const;

/**
 * Hash and Crypto Configuration
 */
export const CRYPTO = {
    /** Default fingerprint length in characters */
    FINGERPRINT_LENGTH: 16,

    /** ID length in characters */
    ID_LENGTH: 8,

    /** Random ID length in bytes */
    RANDOM_ID_BYTES: 16,
} as const;

/**
 * Score and Range Thresholds
 */
export const THRESHOLDS = {
    /** Minimum valid score */
    SCORE_MIN: 0,

    /** Maximum valid score */
    SCORE_MAX: 100,

    /** Minimum security critical count */
    SECURITY_CRITICAL_MIN: 0,
} as const;

/**
 * File Extensions
 */
export const FILE_EXTENSIONS = {
    /** Valid policy file extensions */
    POLICY: ['.yml', '.yaml'] as const,

    /** Valid SARIF file extensions */
    SARIF: ['.sarif', '.json'] as const,

    /** Valid report file extensions */
    REPORT: ['.json', '.html', '.pdf'] as const,
} as const;

/**
 * Reserved Keywords (Prototype Pollution Protection)
 */
export const RESERVED_KEYWORDS = [
    '__proto__',
    'constructor',
    'prototype',
] as const;

/**
 * Blocked Path Segments (Path Traversal Protection)
 */
export const BLOCKED_PATH_SEGMENTS = [
    '..',
    'node_modules',
    '.git',
    '.env',
    '.npm',
    '.ssh',
] as const;

/**
 * Default Allowed Directories
 */
export const DEFAULT_ALLOWED_DIRS = [
    './policies',
    '.',
] as const;

/**
 * Error Messages
 */
export const ERROR_MESSAGES = {
    INVALID_REGEX: 'Invalid regex pattern',
    REGEX_TOO_LONG: 'Regex pattern exceeds maximum length',
    REGEX_UNSAFE: 'Regex pattern contains unsafe patterns',
    PATH_TRAVERSAL: 'Path contains blocked segments',
    INVALID_FILE_EXT: 'Invalid file extension',
    FILE_TOO_LARGE: 'File exceeds maximum size',
    YAML_BOMB: 'Potential YAML bomb detected',
    TOO_MANY_POLICIES: 'Too many policies defined',
    RESERVED_KEYWORD: 'Reserved keyword detected',
    INVALID_URL: 'Invalid URL format',
    SCORE_OUT_OF_RANGE: 'Score must be between 0 and 100',
    INVALID_TIMESTAMP: 'Invalid timestamp format',
} as const;

/**
 * V3 Version Information
 */
export const VERSION_INFO = {
    /** Current v3 version */
    VERSION: '3.0.0',

    /** SARIF schema version */
    SARIF_VERSION: '2.1.0',
} as const;

/**
 * Helper function to get error message with context
 */
export function getErrorMessage(key: keyof typeof ERROR_MESSAGES, context?: string): string {
    const baseMessage = ERROR_MESSAGES[key];
    return context ? `${baseMessage}: ${context}` : baseMessage;
}

/**
 * Helper function to check if value is within score range
 */
export function isValidScore(value: number): boolean {
    return (
        typeof value === 'number' &&
        !isNaN(value) &&
        value >= THRESHOLDS.SCORE_MIN &&
        value <= THRESHOLDS.SCORE_MAX
    );
}

/**
 * Helper function to check if string is a reserved keyword
 */
export function isReservedKeyword(value: string): boolean {
    return RESERVED_KEYWORDS.includes(value as any);
}

/**
 * Helper function to check if path contains blocked segments
 */
export function hasBlockedPathSegment(pathString: string): boolean {
    const segments = pathString.split(/[/\\]/);
    return segments.some(segment => BLOCKED_PATH_SEGMENTS.includes(segment as any));
}
