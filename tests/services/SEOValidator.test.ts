/**
 * Unit Tests for SEOValidator
 *
 * Tests SEO meta tag validation functionality.
 */

import { SEOValidator, SEOResult } from '../../src/services/SEOValidator.js';

// Mock Page object that returns meta tag data
const createMockPage = (meta: Partial<SEOResult['meta']> = {}) => ({
    evaluate: jest.fn().mockResolvedValue({
        title: meta.title ?? 'Test Page Title',
        description: meta.description ?? 'Test description for the page',
        ogTitle: meta.ogTitle ?? 'OG Title',
        ogDescription: meta.ogDescription ?? 'OG Description',
        ogImage: meta.ogImage ?? 'https://example.com/image.jpg',
        twitterCard: meta.twitterCard ?? 'summary_large_image'
    }),
    url: () => 'https://example.com'
});

describe('SEOValidator', () => {
    let validator: SEOValidator;

    beforeEach(() => {
        validator = new SEOValidator();
    });

    describe('check method', () => {
        it('should return valid when all tags present', async () => {
            const mockPage = createMockPage({
                title: 'My Page',
                description: 'A good description that is long enough',
                ogTitle: 'OG Title',
                ogDescription: 'OG Description text here',
                ogImage: 'https://example.com/image.jpg',
                twitterCard: 'summary_large_image'
            });

            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.valid).toBe(true);
            expect(result.missingTags.length).toBe(0);
        });

        it('should flag missing og:title', async () => {
            const mockPage = createMockPage({ ogTitle: null });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('og:title');
        });

        it('should flag missing og:description', async () => {
            const mockPage = createMockPage({ ogDescription: null });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('og:description');
        });

        it('should flag missing og:image', async () => {
            const mockPage = createMockPage({ ogImage: null });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('og:image');
        });

        it('should flag missing twitter:card', async () => {
            const mockPage = createMockPage({ twitterCard: null });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('twitter:card');
        });

        it('should flag missing title', async () => {
            const mockPage = createMockPage({ title: '' });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('<title>');
        });

        it('should flag missing description', async () => {
            const mockPage = createMockPage({ description: null });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags).toContain('meta[description]');
        });
    });

    describe('result structure', () => {
        it('should include url in result', async () => {
            const mockPage = createMockPage({});
            const result = await validator.check(mockPage as any, 'https://test.example.com');

            expect(result.url).toBe('https://test.example.com');
        });

        it('should include valid boolean', async () => {
            const mockPage = createMockPage({});
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(typeof result.valid).toBe('boolean');
        });

        it('should include missingTags array', async () => {
            const mockPage = createMockPage({});
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(Array.isArray(result.missingTags)).toBe(true);
        });

        it('should include warnings array', async () => {
            const mockPage = createMockPage({});
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(Array.isArray(result.warnings)).toBe(true);
        });

        it('should include meta object with extracted values', async () => {
            const mockPage = createMockPage({
                title: 'Test Title',
                ogTitle: 'OG Test Title'
            });
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.meta.title).toBe('Test Title');
            expect(result.meta.ogTitle).toBe('OG Test Title');
        });
    });

    describe('warnings', () => {
        it('should warn on short og:description', async () => {
            const mockPage = createMockPage({ ogDescription: 'Short' });
            const result = await validator.check(mockPage as any, 'https://example.com');

            const hasShortWarning = result.warnings.some(w => w.includes('short'));
            expect(hasShortWarning).toBe(true);
        });
    });

    describe('imageStatus', () => {
        it('should have imageStatus field in result', async () => {
            const mockPage = createMockPage({});
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(['ok', 'missing', 'broken', 'unchecked']).toContain(result.imageStatus);
        });
    });

    describe('multiple missing tags', () => {
        it('should detect all missing tags at once', async () => {
            const mockPage = createMockPage({
                title: '',
                description: null,
                ogTitle: null,
                ogDescription: null,
                ogImage: null,
                twitterCard: null
            });

            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.missingTags.length).toBeGreaterThanOrEqual(5);
            expect(result.valid).toBe(false);
        });
    });

    describe('error handling', () => {
        it('should handle page errors gracefully', async () => {
            const mockPage = {
                evaluate: jest.fn().mockRejectedValue(new Error('Page error')),
                url: () => 'https://example.com'
            };

            // Should not throw
            const result = await validator.check(mockPage as any, 'https://example.com');

            expect(result.url).toBe('https://example.com');
        });
    });
});
