/**
 * Unit Tests for PiiScanner
 *
 * Tests PII (Personally Identifiable Information) detection patterns.
 * Similar pattern to SecretScanner tests.
 */

import { PiiScanner, PiiFinding } from '../../src/services/PiiScanner.js';

describe('PiiScanner', () => {
    let scanner: PiiScanner;

    beforeEach(() => {
        scanner = new PiiScanner();
    });

    describe('IScanner interface', () => {
        it('should have correct name', () => {
            expect(scanner.name).toBe('PiiScanner');
        });

        it('should return empty findings initially', () => {
            expect(scanner.getResults()).toEqual([]);
        });

        it('should clear findings', () => {
            // Trigger a detection via private method
            const scanText = (scanner as any).scanText.bind(scanner);
            scanText('Test SSN: 123-45-6789', 'DOM', 'body');

            expect(scanner.getResults().length).toBeGreaterThan(0);

            scanner.clear();

            expect(scanner.getResults()).toEqual([]);
        });
    });

    describe('SSN detection', () => {
        const scanText = (text: string) => {
            (scanner as any).scanText(text, 'DOM', 'body');
        };

        beforeEach(() => {
            scanner.clear();
        });

        it('should detect valid SSN format', () => {
            scanText('Customer SSN: 123-45-6789');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
            expect(findings[0].type).toBe('SSN');
            expect(findings[0].risk).toBe('High');
            expect(findings[0].redactedMatch).toContain('6789');
        });

        it('should detect multiple SSNs', () => {
            scanText('SSN1: 123-45-6789, SSN2: 987-65-4321');

            const findings = scanner.getResults();
            expect(findings.length).toBe(2);
        });

        it('should NOT detect invalid SSN (000 prefix)', () => {
            scanText('Invalid SSN: 000-45-6789');

            const findings = scanner.getResults();
            expect(findings.length).toBe(0);
        });

        it('should NOT detect invalid SSN (666 prefix)', () => {
            scanText('Invalid SSN: 666-45-6789');

            const findings = scanner.getResults();
            expect(findings.length).toBe(0);
        });

        it('should NOT detect invalid SSN (9xx prefix)', () => {
            scanText('Invalid SSN: 900-45-6789');

            const findings = scanner.getResults();
            expect(findings.length).toBe(0);
        });
    });

    describe('Credit Card detection', () => {
        const scanText = (text: string) => {
            (scanner as any).scanText(text, 'Network', 'https://api.example.com');
        };

        beforeEach(() => {
            scanner.clear();
        });

        it('should detect valid Visa card (Luhn valid)', () => {
            // 4111111111111111 is a well-known Luhn-valid test card
            scanText('Card: 4111-1111-1111-1111');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
            expect(findings[0].type).toBe('CreditCard');
        });

        it('should detect valid card with spaces', () => {
            scanText('Card: 4111 1111 1111 1111');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
        });

        it('should NOT detect Stripe test card (whitelisted)', () => {
            scanText('Test card: 4242-4242-4242-4242');

            const findings = scanner.getResults();
            expect(findings.length).toBe(0);
        });

        it('should NOT detect invalid card (Luhn check fails)', () => {
            // Random digits that fail Luhn
            scanText('Invalid: 1234-5678-9012-3456');

            const findings = scanner.getResults();
            expect(findings.length).toBe(0);
        });
    });

    describe('Phone Number detection', () => {
        const scanText = (text: string) => {
            (scanner as any).scanText(text, 'DOM', 'body');
        };

        beforeEach(() => {
            scanner.clear();
        });

        it('should detect US phone format (xxx) xxx-xxxx', () => {
            scanText('Call us: (555) 123-4567');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
            expect(findings[0].type).toBe('PhoneNumber');
        });

        it('should detect US phone format xxx-xxx-xxxx', () => {
            scanText('Phone: 555-123-4567');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
        });

        it('should detect US phone with +1 prefix', () => {
            scanText('Phone: +1 555-123-4567');

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
        });

        it('should NOT detect whitelisted test phone numbers (555-01xx)', () => {
            scanText('Test phone: 555-0123');

            const findings = scanner.getResults();
            // 555-01xx pattern is whitelisted
            expect(findings.length).toBe(0);
        });
    });

    describe('Luhn algorithm', () => {
        it('should validate known valid card numbers', () => {
            const luhnCheck = (scanner as any).luhnCheck.bind(scanner);

            // Known valid test cards
            expect(luhnCheck('4111111111111111')).toBe(true); // Visa
            expect(luhnCheck('5500000000000004')).toBe(true); // MasterCard
            expect(luhnCheck('340000000000009')).toBe(true);  // Amex
        });

        it('should reject invalid card numbers', () => {
            const luhnCheck = (scanner as any).luhnCheck.bind(scanner);

            expect(luhnCheck('1234567890123456')).toBe(false);
            expect(luhnCheck('0000000000000000')).toBe(true); // Edge case: all zeros passes Luhn
        });
    });

    describe('redaction', () => {
        it('should redact sensitive data showing only last 4 chars', () => {
            const redact = (scanner as any).redact.bind(scanner);

            expect(redact('123-45-6789')).toBe('***-6789');
            expect(redact('4111111111111111')).toBe('***-1111');
        });

        it('should handle short values', () => {
            const redact = (scanner as any).redact.bind(scanner);

            expect(redact('123')).toBe('***');
        });
    });

    describe('deduplication', () => {
        const scanText = (text: string) => {
            (scanner as any).scanText(text, 'DOM', 'body');
        };

        beforeEach(() => {
            scanner.clear();
        });

        it('should not duplicate same finding at same location', () => {
            scanText('SSN: 123-45-6789');
            scanText('SSN: 123-45-6789'); // Same again

            const findings = scanner.getResults();
            expect(findings.length).toBe(1);
        });
    });
});
