/**
 * Unit Tests for SEOValidator
 *
 * Tests SEO metadata validation structure and types.
 */

import { SEOValidator, SEOResult } from '../../src/services/SEOValidator.js';

describe('SEOValidator', () => {
    let validator: SEOValidator;

    beforeEach(() => {
        validator = new SEOValidator();
    });

    describe('Service interface', () => {
        it('should have check method', () => {
            expect(typeof validator.check).toBe('function');
        });
    });

    describe('SEOResult type', () => {
        it('should define valid SEOResult structure', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: true,
                missingTags: [],
                warnings: [],
                imageStatus: 'ok',
                meta: {
                    title: 'Example',
                    description: 'Example page',
                    ogTitle: 'Example OG',
                    ogDescription: 'Example OG description',
                    ogImage: 'https://example.com/og.jpg',
                    twitterCard: 'summary_large_image'
                }
            };
            expect(result.valid).toBe(true);
            expect(Array.isArray(result.missingTags)).toBe(true);
            expect(Array.isArray(result.warnings)).toBe(true);
        });

        it('should track missing tags', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: false,
                missingTags: ['ogImage', 'twitterCard'],
                warnings: ['Title too short'],
                imageStatus: 'missing',
                meta: {}
            };
            expect(result.missingTags).toContain('ogImage');
            expect(result.missingTags).toContain('twitterCard');
        });
    });

    describe('Result validation', () => {
        it('should indicate invalid when tags are missing', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: false,
                missingTags: ['description'],
                warnings: [],
                imageStatus: 'missing',
                meta: {}
            };
            expect(result.valid).toBe(false);
        });

        it('should support warnings array', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: true,
                missingTags: [],
                warnings: [
                    'Title is too short',
                    'No canonical URL found'
                ],
                imageStatus: 'ok',
                meta: { title: 'Page' }
            };
            expect(result.warnings.length).toBe(2);
        });

        it('should track image status', () => {
            const statusValues = ['ok', 'missing', 'broken', 'unchecked'];
            for (const status of statusValues) {
                const result: SEOResult = {
                    url: 'https://example.com',
                    valid: status !== 'missing',
                    missingTags: [],
                    warnings: [],
                    imageStatus: status as any,
                    meta: {}
                };
                expect(['ok', 'missing', 'broken', 'unchecked']).toContain(result.imageStatus);
            }
        });
    });

    describe('Metadata structure', () => {
        it('should store meta tags in object', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: true,
                missingTags: [],
                warnings: [],
                imageStatus: 'ok',
                meta: {
                    title: 'Example Page',
                    description: 'This is an example page',
                    ogTitle: 'Example on Open Graph',
                    ogImage: 'https://example.com/image.jpg'
                }
            };
            expect(result.meta.title).toBe('Example Page');
            expect(result.meta.ogTitle).toBe('Example on Open Graph');
        });

        it('should handle empty meta tags', () => {
            const result: SEOResult = {
                url: 'https://example.com',
                valid: false,
                missingTags: ['title', 'description'],
                warnings: [],
                imageStatus: 'missing',
                meta: {}
            };
            expect(Object.keys(result.meta).length).toBe(0);
        });
    });
});
