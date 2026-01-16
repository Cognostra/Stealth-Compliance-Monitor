/**
 * Redaction utilities for logs and artifacts
 */

const KEY_PATTERNS: RegExp[] = [
    /AKIA[0-9A-Z]{16}/g, // AWS Access Key ID
    /(?:ASIA|A3T[A-Z0-9])[A-Z0-9]{16}/g, // AWS temp keys
    /ghp_[A-Za-z0-9]{36}/g, // GitHub token
    /sk_live_[A-Za-z0-9]{24,}/g, // Stripe live
    /sk_test_[A-Za-z0-9]{24,}/g, // Stripe test
    /AIza[0-9A-Za-z\-_]{35}/g, // Google API key
    /xox[baprs]-[A-Za-z0-9-]{10,48}/g, // Slack token
    /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, // JWT
];

const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;

const SENSITIVE_KEYS = new Set([
    'password',
    'pass',
    'token',
    'authorization',
    'apiKey',
    'apikey',
    'secret',
    'cookie',
    'set-cookie',
    'session',
]);

export function redactString(value: string): string {
    let redacted = value;
    for (const pattern of KEY_PATTERNS) {
        redacted = redacted.replace(pattern, '[REDACTED]');
    }
    redacted = redacted.replace(EMAIL_PATTERN, '[REDACTED_EMAIL]');
    return redacted;
}

export function redactObject(value: unknown): unknown {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return redactString(value);
    if (typeof value !== 'object') return value;

    if (Array.isArray(value)) {
        return value.map(item => redactObject(item));
    }

    const obj = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
        if (SENSITIVE_KEYS.has(key.toLowerCase())) {
            result[key] = '[REDACTED]';
        } else {
            result[key] = redactObject(val);
        }
    }
    return result;
}
