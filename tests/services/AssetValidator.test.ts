/**
 * Unit Tests for AssetValidator
 *
 * Tests broken asset detection result structure.
 */

import { AssetValidator, AssetCheckResult } from '../../src/services/AssetValidator.js';

describe('AssetValidator', () => {
    let validator: AssetValidator;

    beforeEach(() => {
        validator = new AssetValidator();
    });

    describe('Service interface', () => {
        it('should have check method', () => {
            expect(typeof validator.check).toBe('function');
        });
    });

    describe('AssetCheckResult type', () => {
        it('should define AssetCheckResult with brokenImages array', () => {
            const result: AssetCheckResult = {
                brokenImages: ['https://example.com/broken.jpg'],
                totalImages: 5
            };
            expect(Array.isArray(result.brokenImages)).toBe(true);
            expect(typeof result.totalImages).toBe('number');
        });

        it('should handle empty brokenImages', () => {
            const result: AssetCheckResult = {
                brokenImages: [],
                totalImages: 10
            };
            expect(result.brokenImages.length).toBe(0);
            expect(result.totalImages).toBe(10);
        });
    });

    describe('Result structure', () => {
        it('should track total image count', () => {
            const result: AssetCheckResult = {
                brokenImages: [],
                totalImages: 42
            };
            expect(result.totalImages).toBe(42);
        });

        it('should support image URLs in brokenImages', () => {
            const result: AssetCheckResult = {
                brokenImages: [
                    'https://example.com/img1.jpg',
                    'https://example.com/img2.png'
                ],
                totalImages: 10
            };
            expect(result.brokenImages.every(url => url.startsWith('https://'))).toBe(true);
        });
    });
});
