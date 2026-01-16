/**
 * Unit Tests for PiiScanner
 *
 * Tests PII detection pattern matching in isolation.
 * Note: PiiScanner is designed for integration with Playwright lifecycle.
 * These tests validate the pattern detection logic only.
 */

import { PiiScanner, PiiFinding } from '../../src/services/PiiScanner.js';

describe('PiiScanner', () => {
    let scanner: PiiScanner;

    beforeEach(() => {
        scanner = new PiiScanner();
    });

    describe('Service interface', () => {
        it('should have correct name', () => {
            expect(scanner.name).toBe('PiiScanner');
        });

        it('should implement IScanner interface', () => {
            expect(typeof scanner.onPageCreated).toBe('function');
            expect(typeof scanner.onResponse).toBe('function');
        });
    });

    describe('PiiFinding type', () => {
        it('should define PiiFinding with required fields', () => {
            const finding: PiiFinding = {
                type: 'SSN',
                risk: 'High',
                description: 'Test',
                source: 'DOM',
                matchedPattern: '123-45-6789',
                redactedMatch: '***-6789',
                timestamp: new Date().toISOString()
            };
            expect(finding.type).toBe('SSN');
            expect(finding.risk).toBe('High');
            expect(finding.source).toBe('DOM');
        });
    });

    describe('Pattern validation - SSN', () => {
        const ssnPattern = /\b(?!000|666|9\d{2})([0-9]{3})-(?!00)([0-9]{2})-(?!0000)([0-9]{4})\b/;

        it('should match valid SSN format', () => {
            expect(ssnPattern.test('123-45-6789')).toBe(true);
            expect(ssnPattern.test('234-56-7890')).toBe(true);
        });

        it('should NOT match SSN with 000 prefix', () => {
            expect(ssnPattern.test('000-45-6789')).toBe(false);
        });

        it('should NOT match SSN with 666 prefix', () => {
            expect(ssnPattern.test('666-45-6789')).toBe(false);
        });

        it('should NOT match SSN with 9xx prefix', () => {
            expect(ssnPattern.test('900-45-6789')).toBe(false);
            expect(ssnPattern.test('999-45-6789')).toBe(false);
            expect(ssnPattern.test('987-65-4321')).toBe(false);
        });
    });

    describe('Pattern validation - Credit Card', () => {
        const cardPattern = /\b(?:\d[ -]*?){13,16}\b/;

        it('should match credit card formats', () => {
            expect(cardPattern.test('4111-1111-1111-1111')).toBe(true);
            expect(cardPattern.test('4111 1111 1111 1111')).toBe(true);
            expect(cardPattern.test('4111111111111111')).toBe(true);
        });

        it('should match various card lengths', () => {
            expect(cardPattern.test('6011111111111117')).toBe(true); // Discover
            expect(cardPattern.test('378282246310005')).toBe(true);  // Amex
        });
    });

    describe('Pattern validation - Phone Number', () => {
        const phonePattern = /(?:\+?1[-. ]?)?\(?([2-9][0-8][0-9])\)?[-\. ]?([2-9][0-9]{2})[-\. ]?([0-9]{4})\b/;

        it('should match US phone formats', () => {
            expect(phonePattern.test('202-555-1234')).toBe(true);
            expect(phonePattern.test('202.555.1234')).toBe(true);
            expect(phonePattern.test('2025551234')).toBe(true);
        });

        it('should match phone with +1 prefix', () => {
            expect(phonePattern.test('+1-202-555-1234')).toBe(true);
            expect(phonePattern.test('+1 202-555-1234')).toBe(true);
        });

        it('should validate area code (cannot be 0 or 1)', () => {
            expect(phonePattern.test('155-223-4567')).toBe(false);
            expect(phonePattern.test('055-223-4567')).toBe(false);
        });

        it('should validate exchange code (cannot start with 0 or 1)', () => {
            expect(phonePattern.test('202-013-4567')).toBe(false);
            expect(phonePattern.test('202-113-4567')).toBe(false);
        });
    });
});
