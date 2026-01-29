/**
 * Cryptographic Utilities
 *
 * Provides secure hashing functions for generating fingerprints and IDs.
 * Uses Node.js crypto module with SHA-256 for collision resistance.
 */

import crypto from 'crypto';

/**
 * Generate a secure fingerprint from multiple components
 *
 * Uses SHA-256 hashing for cryptographic strength and collision resistance.
 * Much more secure than simple Java-style hash functions.
 *
 * @param components - Array of strings to hash together
 * @param length - Length of the output fingerprint (default: 16 chars)
 * @returns Hexadecimal fingerprint string
 *
 * @example
 * ```typescript
 * const fingerprint = generateFingerprint(['xss', 'https://example.com', 'XSS Attack']);
 * // Returns: "a1b2c3d4e5f6g7h8"
 * ```
 */
export function generateFingerprint(components: string[], length: number = 16): string {
    const combined = components.join('|');
    const hash = crypto.createHash('sha256').update(combined, 'utf8').digest('hex');
    return hash.slice(0, length);
}

/**
 * Generate a secure hash from a single string
 *
 * @param input - The string to hash
 * @param algorithm - Hash algorithm to use (default: 'sha256')
 * @param encoding - Output encoding (default: 'hex')
 * @returns The hash string
 *
 * @example
 * ```typescript
 * const hash = generateHash('my-data');
 * // Returns full SHA-256 hash
 * ```
 */
export function generateHash(
    input: string,
    algorithm: 'sha256' | 'sha512' | 'md5' = 'sha256',
    encoding: 'hex' | 'base64' = 'hex'
): string {
    return crypto.createHash(algorithm).update(input, 'utf8').digest(encoding);
}

/**
 * Generate a unique ID from name and optional URL
 *
 * Replacement for weak Java-style hash generation.
 * Produces consistent, collision-resistant IDs.
 *
 * @param name - The primary identifier (e.g., finding name, alert type)
 * @param url - Optional URL or additional context
 * @returns 8-character hexadecimal ID
 *
 * @example
 * ```typescript
 * const id = generateId('SQL Injection', 'https://example.com/login');
 * // Returns: "f8a3b2c1"
 * ```
 */
export function generateId(name: string, url?: string): string {
    const components = url ? [name, url] : [name];
    return generateFingerprint(components, 8);
}

/**
 * Generate a content-based hash for deduplication
 *
 * Useful for detecting duplicate findings or content.
 *
 * @param content - The content to hash
 * @returns Full SHA-256 hash
 *
 * @example
 * ```typescript
 * const contentHash = generateContentHash(JSON.stringify(finding));
 * ```
 */
export function generateContentHash(content: string): string {
    return generateHash(content, 'sha256', 'hex');
}

/**
 * Compare two hashes in constant time to prevent timing attacks
 *
 * @param hash1 - First hash to compare
 * @param hash2 - Second hash to compare
 * @returns True if hashes match
 */
export function compareHashes(hash1: string, hash2: string): boolean {
    if (hash1.length !== hash2.length) {
        return false;
    }

    try {
        return crypto.timingSafeEqual(Buffer.from(hash1), Buffer.from(hash2));
    } catch {
        // If conversion fails, fall back to simple comparison
        return hash1 === hash2;
    }
}

/**
 * Generate a cryptographically secure random ID
 *
 * @param length - Length in bytes (default: 16, produces 32 hex chars)
 * @returns Random hexadecimal string
 *
 * @example
 * ```typescript
 * const randomId = generateRandomId();
 * // Returns: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
 * ```
 */
export function generateRandomId(length: number = 16): string {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a UUID v4 (random)
 *
 * @returns UUID string
 *
 * @example
 * ```typescript
 * const uuid = generateUuid();
 * // Returns: "550e8400-e29b-41d4-a716-446655440000"
 * ```
 */
export function generateUuid(): string {
    return crypto.randomUUID();
}
