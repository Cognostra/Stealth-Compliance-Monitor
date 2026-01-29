/**
 * Security Validation Utilities
 *
 * Provides comprehensive input validation to prevent:
 * - ReDoS (Regular Expression Denial of Service)
 * - Path Traversal attacks
 * - YAML Bomb attacks
 * - Prototype Pollution
 * - Type safety violations
 */

import * as fs from 'fs';
import * as path from 'path';
import type { AuditReport } from '../../types/index.js';
import {
    LIMITS,
    TIMEOUTS,
    RESERVED_KEYWORDS,
    BLOCKED_PATH_SEGMENTS,
} from './constants.js';

/**
 * Regex timeout in milliseconds (exported for compatibility)
 */
export const REGEX_TIMEOUT_MS = TIMEOUTS.REGEX_TIMEOUT_MS;

/**
 * Dangerous regex patterns that can cause catastrophic backtracking
 */
const DANGEROUS_REGEX_PATTERNS = [
    /(\([^)]*[+*][^)]*\))[+*]/,           // Nested quantifiers: (a+)+, (a*)*
    /\.[*+]\.[*+]/,                        // Multiple wildcards: .*.*
    /(\w+\*)+\+/,                          // Chained quantifiers
    /(\([^)]*\|[^)]*\)){2,}[+*]/,         // Alternation with quantifiers
];

/**
 * Result of regex safety validation
 */
export interface RegexSafetyResult {
    safe: boolean;
    reason?: string;
}

/**
 * Result of file path validation
 */
export interface FilePathValidationResult {
    valid: boolean;
    normalizedPath?: string;
    error?: string;
}

/**
 * Result of YAML safety validation
 */
export interface YamlSafetyResult {
    safe: boolean;
    error?: string;
}

/**
 * Options for file path validation
 */
export interface FilePathValidationOptions {
    /** Allowed base directories (from POLICY_ALLOWED_DIRS env var) */
    allowedDirs?: string[];
    /** Required file extensions */
    requiredExtensions?: string[];
    /** Whether to check if file exists */
    mustExist?: boolean;
}

/**
 * Validates regex pattern safety to prevent ReDoS attacks
 *
 * Checks for:
 * - Patterns exceeding maximum length
 * - Catastrophic backtracking patterns
 * - Nested quantifiers
 *
 * @param pattern - The regex pattern to validate
 * @returns Validation result with safety status and reason if unsafe
 *
 * @example
 * ```typescript
 * const result = validateRegexSafety('(a+)+');
 * if (!result.safe) {
 *   throw new Error(`Unsafe regex: ${result.reason}`);
 * }
 * ```
 */
export function validateRegexSafety(pattern: string): RegexSafetyResult {
    // Check length limit
    if (pattern.length > LIMITS.REGEX_MAX_LENGTH) {
        return {
            safe: false,
            reason: `Pattern exceeds maximum length of ${LIMITS.REGEX_MAX_LENGTH} characters`,
        };
    }

    // Check for dangerous patterns
    for (const dangerousPattern of DANGEROUS_REGEX_PATTERNS) {
        if (dangerousPattern.test(pattern)) {
            return {
                safe: false,
                reason: 'Pattern contains catastrophic backtracking risk (nested quantifiers)',
            };
        }
    }

    // Test compilation
    try {
        new RegExp(pattern);
    } catch (error) {
        return {
            safe: false,
            reason: `Invalid regex syntax: ${error instanceof Error ? error.message : String(error)}`,
        };
    }

    return { safe: true };
}

/**
 * Validates file path to prevent path traversal attacks
 *
 * Security checks:
 * - Blocks path traversal attempts (..)
 * - Validates against allowed directories
 * - Blocks sensitive directories (node_modules, .git, .env, etc.)
 * - Enforces file extension requirements
 *
 * @param filePath - The file path to validate
 * @param options - Validation options
 * @returns Validation result with normalized path if valid
 *
 * @example
 * ```typescript
 * const result = validateFilePath('/etc/passwd', {
 *   allowedDirs: ['./policies'],
 *   requiredExtensions: ['.yml', '.yaml']
 * });
 * if (!result.valid) {
 *   throw new Error(result.error);
 * }
 * ```
 */
export function validateFilePath(
    filePath: string,
    options: FilePathValidationOptions = {}
): FilePathValidationResult {
    const { allowedDirs = [], requiredExtensions = ['.yml', '.yaml'], mustExist = true } = options;

    // Normalize path
    const normalizedPath = path.resolve(filePath);

    // Check for blocked segments
    const segments = normalizedPath.split(path.sep);
    for (const segment of segments) {
        if (BLOCKED_PATH_SEGMENTS.includes(segment as any)) {
            return {
                valid: false,
                error: `Path contains blocked segment: ${segment}`,
            };
        }
    }

    // Check file extension
    if (requiredExtensions.length > 0) {
        const ext = path.extname(normalizedPath);
        if (!requiredExtensions.includes(ext)) {
            return {
                valid: false,
                error: `File must have one of these extensions: ${requiredExtensions.join(', ')}`,
            };
        }
    }

    // Check against allowed directories
    if (allowedDirs.length > 0) {
        const isInAllowedDir = allowedDirs.some((allowedDir) => {
            const resolvedAllowedDir = path.resolve(allowedDir);
            return normalizedPath.startsWith(resolvedAllowedDir);
        });

        if (!isInAllowedDir) {
            return {
                valid: false,
                error: `Path must be within allowed directories: ${allowedDirs.join(', ')}`,
            };
        }
    } else {
        // If no allowed dirs specified, default to current working directory
        const cwd = process.cwd();
        if (!normalizedPath.startsWith(cwd)) {
            return {
                valid: false,
                error: `Path must be within current working directory: ${cwd}`,
            };
        }
    }

    // Check if file exists (if required)
    if (mustExist && !fs.existsSync(normalizedPath)) {
        return {
            valid: false,
            error: `File does not exist: ${normalizedPath}`,
        };
    }

    return {
        valid: true,
        normalizedPath,
    };
}

/**
 * Validates YAML content to prevent YAML bomb attacks
 *
 * Checks for:
 * - File size limits
 * - Excessive alias usage (billion laughs attack)
 * - Repeated alias patterns
 *
 * @param content - The YAML content to validate
 * @returns Validation result with safety status
 *
 * @example
 * ```typescript
 * const yamlContent = fs.readFileSync('policy.yml', 'utf-8');
 * const result = validateYamlSafety(yamlContent);
 * if (!result.safe) {
 *   throw new Error(`Unsafe YAML: ${result.error}`);
 * }
 * ```
 */
export function validateYamlSafety(content: string): YamlSafetyResult {
    // Check size limit
    const sizeInBytes = Buffer.byteLength(content, 'utf-8');
    if (sizeInBytes > LIMITS.YAML_MAX_SIZE_BYTES) {
        return {
            safe: false,
            error: `YAML content exceeds maximum size of ${LIMITS.YAML_MAX_SIZE_BYTES / 1024 / 1024}MB`,
        };
    }

    // Count YAML aliases (references starting with *)
    const aliasMatches = content.match(/\*\w+/g);
    const aliasCount = aliasMatches ? aliasMatches.length : 0;

    if (aliasCount > LIMITS.YAML_MAX_ALIASES) {
        return {
            safe: false,
            error: `Excessive YAML aliases detected (${aliasCount} > ${LIMITS.YAML_MAX_ALIASES}). Potential YAML bomb attack.`,
        };
    }

    // Detect repeated alias patterns (billion laughs signature)
    const repeatedAliasPattern = /(\*\w+,\s*){10,}/;
    if (repeatedAliasPattern.test(content)) {
        return {
            safe: false,
            error: 'Repeated alias pattern detected. Potential YAML bomb attack.',
        };
    }

    return { safe: true };
}

/**
 * Type guard to validate AuditReport structure
 *
 * Performs runtime validation of AuditReport objects to ensure
 * they contain all required fields with correct types.
 *
 * @param value - The value to check
 * @returns True if value is a valid AuditReport
 *
 * @example
 * ```typescript
 * if (!isAuditReport(data)) {
 *   throw new Error('Invalid audit report structure');
 * }
 * // TypeScript now knows data is AuditReport
 * console.log(data.targetUrl);
 * ```
 */
export function isAuditReport(value: unknown): value is AuditReport {
    if (!value || typeof value !== 'object') {
        return false;
    }

    const record = value as Record<string, unknown>;

    // Check required top-level fields
    if (
        typeof record.timestamp !== 'string' ||
        typeof record.targetUrl !== 'string' ||
        typeof record.duration !== 'number' ||
        typeof record.overallScore !== 'number' ||
        typeof record.passed !== 'boolean'
    ) {
        return false;
    }

    // Check performance object
    if (
        !record.performance ||
        typeof record.performance !== 'object' ||
        typeof (record.performance as Record<string, unknown>).score !== 'number'
    ) {
        return false;
    }

    // Check accessibility object
    if (
        !record.accessibility ||
        typeof record.accessibility !== 'object' ||
        typeof (record.accessibility as Record<string, unknown>).score !== 'number' ||
        !Array.isArray((record.accessibility as Record<string, unknown>).issues)
    ) {
        return false;
    }

    // Check security object
    if (
        !record.security ||
        typeof record.security !== 'object' ||
        typeof (record.security as Record<string, unknown>).score !== 'number' ||
        !Array.isArray((record.security as Record<string, unknown>).headers) ||
        !Array.isArray((record.security as Record<string, unknown>).alerts)
    ) {
        return false;
    }

    // Check userFlows array
    if (!Array.isArray(record.userFlows)) {
        return false;
    }

    return true;
}

/**
 * Validates that a string is not a reserved keyword
 *
 * Prevents prototype pollution attacks by rejecting reserved
 * JavaScript object property names.
 *
 * @param value - The string to validate
 * @returns True if the string is a reserved keyword
 *
 * @example
 * ```typescript
 * if (isReservedKeyword('__proto__')) {
 *   throw new Error('Reserved keyword detected');
 * }
 * ```
 */
export function isReservedKeyword(value: string): boolean {
    return RESERVED_KEYWORDS.includes(value as any);
}

/**
 * Validates a URL string format
 *
 * Uses native URL constructor for validation.
 *
 * @param urlString - The URL string to validate
 * @returns True if the URL is valid
 *
 * @example
 * ```typescript
 * if (!isValidUrl('https://example.com')) {
 *   throw new Error('Invalid URL');
 * }
 * ```
 */
export function isValidUrl(urlString: string): boolean {
    try {
        new URL(urlString);
        return true;
    } catch {
        return false;
    }
}

/**
 * Validates a number is within a specified range
 *
 * @param value - The number to validate
 * @param min - Minimum allowed value (inclusive)
 * @param max - Maximum allowed value (inclusive)
 * @returns True if the value is within range
 *
 * @example
 * ```typescript
 * if (!isInRange(score, 0, 100)) {
 *   throw new Error('Score must be between 0 and 100');
 * }
 * ```
 */
export function isInRange(value: number, min: number, max: number): boolean {
    return typeof value === 'number' && !isNaN(value) && value >= min && value <= max;
}
