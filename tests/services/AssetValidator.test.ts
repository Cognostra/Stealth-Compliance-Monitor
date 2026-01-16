/**
 * Unit Tests for AssetValidator
 *
 * Tests broken asset detection functionality.
 */

import { AssetValidator, AssetCheckResult } from '../../src/services/AssetValidator.js';

// Mock Page object
const createMockPage = (result: AssetCheckResult) => ({
    evaluate: jest.fn().mockResolvedValue(result),
    url: () => 'https://example.com'
});

describe('AssetValidator', () => {
    let validator: AssetValidator;

    beforeEach(() => {
        validator = new AssetValidator();
    });

    describe('check method', () => {
        it('should detect broken images', async () => {
            const mockPage = createMockPage({
                brokenImages: ['https://example.com/broken.jpg'],
                totalImages: 5
            });

            const result = await validator.check(mockPage as any);

            expect(result.brokenImages.length).toBe(1);
            expect(result.brokenImages[0]).toBe('https://example.com/broken.jpg');
        });

        it('should detect multiple broken images', async () => {
            const mockPage = createMockPage({
                brokenImages: [
                    'https://example.com/broken1.jpg',
                    'https://example.com/broken2.png',
                    'https://example.com/broken3.gif'
                ],
                totalImages: 10
            });

            const result = await validator.check(mockPage as any);

            expect(result.brokenImages.length).toBe(3);
        });

        it('should return empty when no broken images', async () => {
            const mockPage = createMockPage({
                brokenImages: [],
                totalImages: 5
            });

            const result = await validator.check(mockPage as any);

            expect(result.brokenImages).toEqual([]);
        });

        it('should return total image count', async () => {
            const mockPage = createMockPage({
                brokenImages: ['https://example.com/broken.jpg'],
                totalImages: 15
            });

            const result = await validator.check(mockPage as any);

            expect(result.totalImages).toBe(15);
        });

        it('should handle pages with no images', async () => {
            const mockPage = createMockPage({
                brokenImages: [],
                totalImages: 0
            });

            const result = await validator.check(mockPage as any);

            expect(result.totalImages).toBe(0);
            expect(result.brokenImages).toEqual([]);
        });

        it('should handle errors gracefully', async () => {
            const mockPage = {
                evaluate: jest.fn().mockRejectedValue(new Error('Page error')),
                url: () => 'https://example.com'
            };

            const result = await validator.check(mockPage as any);

            // Should return safe defaults on error
            expect(result.brokenImages).toEqual([]);
            expect(result.totalImages).toBe(0);
        });
    });

    describe('result structure', () => {
        it('should include brokenImages array', async () => {
            const mockPage = createMockPage({
                brokenImages: ['https://example.com/img.jpg'],
                totalImages: 1
            });

            const result = await validator.check(mockPage as any);

            expect(Array.isArray(result.brokenImages)).toBe(true);
        });

        it('should include totalImages count', async () => {
            const mockPage = createMockPage({
                brokenImages: [],
                totalImages: 42
            });

            const result = await validator.check(mockPage as any);

            expect(typeof result.totalImages).toBe('number');
        });
    });
});
