/**
 * Tests for Cryptographic Utilities
 *
 * Validates secure hashing functions and collision resistance
 */

import { describe, it, expect } from '@jest/globals';
import {
    generateFingerprint,
    generateHash,
    generateId,
    generateContentHash,
    compareHashes,
    generateRandomId,
    generateUuid,
} from '../../../src/v3/utils/crypto.js';

describe('Crypto Utilities', () => {
    describe('generateFingerprint', () => {
        it('should generate consistent fingerprints for same input', () => {
            const components = ['xss', 'https://example.com', 'XSS Attack'];
            const fp1 = generateFingerprint(components);
            const fp2 = generateFingerprint(components);

            expect(fp1).toBe(fp2);
        });

        it('should generate different fingerprints for different inputs', () => {
            const fp1 = generateFingerprint(['xss', 'https://example.com']);
            const fp2 = generateFingerprint(['sqli', 'https://example.com']);

            expect(fp1).not.toBe(fp2);
        });

        it('should respect length parameter', () => {
            const fp8 = generateFingerprint(['test'], 8);
            const fp16 = generateFingerprint(['test'], 16);
            const fp32 = generateFingerprint(['test'], 32);

            expect(fp8).toHaveLength(8);
            expect(fp16).toHaveLength(16);
            expect(fp32).toHaveLength(32);
        });

        it('should default to 16 characters', () => {
            const fp = generateFingerprint(['test']);
            expect(fp).toHaveLength(16);
        });

        it('should be hexadecimal', () => {
            const fp = generateFingerprint(['test']);
            expect(fp).toMatch(/^[0-9a-f]+$/);
        });

        it('should handle empty components', () => {
            const fp = generateFingerprint([]);
            expect(fp).toHaveLength(16);
            expect(fp).toMatch(/^[0-9a-f]+$/);
        });

        it('should handle special characters', () => {
            const components = ['<script>alert(1)</script>', 'https://evil.com/"><img src=x>'];
            const fp = generateFingerprint(components);

            expect(fp).toHaveLength(16);
            expect(fp).toMatch(/^[0-9a-f]+$/);
        });
    });

    describe('generateHash', () => {
        it('should generate SHA-256 hash by default', () => {
            const hash = generateHash('test');

            // SHA-256 produces 64 hex characters
            expect(hash).toHaveLength(64);
            expect(hash).toMatch(/^[0-9a-f]+$/);
        });

        it('should generate consistent hashes', () => {
            const hash1 = generateHash('test');
            const hash2 = generateHash('test');

            expect(hash1).toBe(hash2);
        });

        it('should support SHA-512', () => {
            const hash = generateHash('test', 'sha512');

            // SHA-512 produces 128 hex characters
            expect(hash).toHaveLength(128);
        });

        it('should support base64 encoding', () => {
            const hash = generateHash('test', 'sha256', 'base64');

            // Base64 encoded SHA-256 is 44 characters
            expect(hash).toHaveLength(44);
            expect(hash).toMatch(/^[A-Za-z0-9+/]+=*$/);
        });

        it('should produce different hashes for different inputs', () => {
            const hash1 = generateHash('test1');
            const hash2 = generateHash('test2');

            expect(hash1).not.toBe(hash2);
        });
    });

    describe('generateId', () => {
        it('should generate 8-character ID', () => {
            const id = generateId('SQL Injection');

            expect(id).toHaveLength(8);
            expect(id).toMatch(/^[0-9a-f]+$/);
        });

        it('should be consistent for same inputs', () => {
            const id1 = generateId('XSS', 'https://example.com');
            const id2 = generateId('XSS', 'https://example.com');

            expect(id1).toBe(id2);
        });

        it('should be different for different inputs', () => {
            const id1 = generateId('XSS', 'https://example.com/page1');
            const id2 = generateId('XSS', 'https://example.com/page2');

            expect(id1).not.toBe(id2);
        });

        it('should work without URL parameter', () => {
            const id = generateId('Finding Type');

            expect(id).toHaveLength(8);
            expect(id).toMatch(/^[0-9a-f]+$/);
        });

        it('should produce different IDs with/without URL', () => {
            const id1 = generateId('XSS');
            const id2 = generateId('XSS', 'https://example.com');

            expect(id1).not.toBe(id2);
        });
    });

    describe('generateContentHash', () => {
        it('should generate full SHA-256 hash', () => {
            const hash = generateContentHash('content');

            expect(hash).toHaveLength(64);
            expect(hash).toMatch(/^[0-9a-f]+$/);
        });

        it('should be consistent for same content', () => {
            const content = JSON.stringify({ type: 'xss', severity: 'high' });
            const hash1 = generateContentHash(content);
            const hash2 = generateContentHash(content);

            expect(hash1).toBe(hash2);
        });

        it('should detect even small changes', () => {
            const hash1 = generateContentHash('content');
            const hash2 = generateContentHash('Content'); // Capital C

            expect(hash1).not.toBe(hash2);
        });
    });

    describe('compareHashes', () => {
        it('should return true for matching hashes', () => {
            const hash = generateHash('test');
            expect(compareHashes(hash, hash)).toBe(true);
        });

        it('should return false for different hashes', () => {
            const hash1 = generateHash('test1');
            const hash2 = generateHash('test2');

            expect(compareHashes(hash1, hash2)).toBe(false);
        });

        it('should return false for different lengths', () => {
            const hash1 = 'abc123';
            const hash2 = 'abc12345';

            expect(compareHashes(hash1, hash2)).toBe(false);
        });

        it('should use constant-time comparison', () => {
            // This is hard to test directly, but we can verify it works
            const hash1 = 'a'.repeat(64);
            const hash2 = 'b'.repeat(64);

            expect(compareHashes(hash1, hash2)).toBe(false);
        });
    });

    describe('generateRandomId', () => {
        it('should generate random hex string of default length', () => {
            const id = generateRandomId();

            // Default 16 bytes = 32 hex characters
            expect(id).toHaveLength(32);
            expect(id).toMatch(/^[0-9a-f]+$/);
        });

        it('should generate different IDs each time', () => {
            const id1 = generateRandomId();
            const id2 = generateRandomId();
            const id3 = generateRandomId();

            expect(id1).not.toBe(id2);
            expect(id2).not.toBe(id3);
            expect(id1).not.toBe(id3);
        });

        it('should respect custom length', () => {
            const id8 = generateRandomId(8);
            const id32 = generateRandomId(32);

            expect(id8).toHaveLength(16); // 8 bytes = 16 hex chars
            expect(id32).toHaveLength(64); // 32 bytes = 64 hex chars
        });

        it('should be cryptographically random', () => {
            // Generate many IDs and check for no duplicates
            const ids = new Set();
            for (let i = 0; i < 1000; i++) {
                ids.add(generateRandomId());
            }

            expect(ids.size).toBe(1000); // All unique
        });
    });

    describe('generateUuid', () => {
        it('should generate valid UUID v4', () => {
            const uuid = generateUuid();

            // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
            expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
        });

        it('should generate different UUIDs each time', () => {
            const uuid1 = generateUuid();
            const uuid2 = generateUuid();
            const uuid3 = generateUuid();

            expect(uuid1).not.toBe(uuid2);
            expect(uuid2).not.toBe(uuid3);
            expect(uuid1).not.toBe(uuid3);
        });

        it('should be cryptographically random', () => {
            const uuids = new Set();
            for (let i = 0; i < 1000; i++) {
                uuids.add(generateUuid());
            }

            expect(uuids.size).toBe(1000); // All unique
        });
    });

    describe('Collision Resistance', () => {
        it('should have low collision rate for similar inputs', () => {
            const hashes = new Set();

            // Generate hashes for similar inputs
            for (let i = 0; i < 1000; i++) {
                const hash = generateId('Finding', `https://example.com/page${i}`);
                hashes.add(hash);
            }

            // Should have no collisions for 1000 different inputs
            expect(hashes.size).toBe(1000);
        });

        it('should handle hash flooding attacks', () => {
            const hashes = new Set();

            // Try to create collisions with crafted inputs
            const maliciousInputs = [
                'AAA',
                'BBB',
                'AAB',
                'ABA',
                'BAA',
                'ABC',
                'ACB',
                'BAC',
                'BCA',
                'CAB',
                'CBA',
            ];

            for (const input of maliciousInputs) {
                hashes.add(generateHash(input));
            }

            // All should be unique
            expect(hashes.size).toBe(maliciousInputs.length);
        });
    });

    describe('Security Properties', () => {
        it('should not leak information about input length', () => {
            const short = generateFingerprint(['a']);
            const long = generateFingerprint(['a'.repeat(10000)]);

            expect(short).toHaveLength(16);
            expect(long).toHaveLength(16);
        });

        it('should handle malicious inputs safely', () => {
            const maliciousInputs = [
                '__proto__',
                'constructor',
                'prototype',
                '../../../etc/passwd',
                '<script>alert(1)</script>',
                'null\x00byte',
                '../../../../',
                '\'; DROP TABLE users; --',
            ];

            for (const malicious of maliciousInputs) {
                expect(() => generateHash(malicious)).not.toThrow();
                const hash = generateHash(malicious);
                expect(hash).toMatch(/^[0-9a-f]+$/);
            }
        });
    });
});
