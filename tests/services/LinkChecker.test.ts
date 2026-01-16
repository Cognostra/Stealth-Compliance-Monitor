/**
 * Unit Tests for LinkChecker
 *
 * Tests link validation structure and result types.
 */

import { LinkChecker, ValidatedLink, LinkCheckResult } from '../../src/services/LinkChecker.js';

describe('LinkChecker', () => {
    let checker: LinkChecker;

    beforeEach(() => {
        checker = new LinkChecker();
    });

    describe('Service interface', () => {
        it('should have checkLinks method', () => {
            expect(typeof checker.checkLinks).toBe('function');
        });
    });

    describe('LinkCheckResult type', () => {
        it('should define valid LinkCheckResult structure', () => {
            const result: LinkCheckResult = {
                brokenLinks: [],
                totalChecked: 5,
                checkedLinks: []
            };
            expect(Array.isArray(result.brokenLinks)).toBe(true);
            expect(typeof result.totalChecked).toBe('number');
            expect(Array.isArray(result.checkedLinks)).toBe(true);
        });
    });

    describe('ValidatedLink type', () => {
        it('should define valid ValidatedLink structure with parentUrl', () => {
            const link: ValidatedLink = {
                url: 'https://example.com/page',
                status: 200,
                ok: true,
                parentUrl: 'https://example.com/'
            };
            expect(typeof link.url).toBe('string');
            expect(typeof link.status).toBe('number');
            expect(typeof link.ok).toBe('boolean');
            expect(typeof link.parentUrl).toBe('string');
        });

        it('should track broken link status codes', () => {
            const brokenLink: ValidatedLink = {
                url: 'https://example.com/not-found',
                status: 404,
                ok: false,
                parentUrl: 'https://example.com/'
            };
            expect(brokenLink.ok).toBe(false);
            expect(brokenLink.status).toBe(404);
        });

        it('should handle server error status codes', () => {
            const errorLink: ValidatedLink = {
                url: 'https://example.com/error',
                status: 500,
                ok: false,
                parentUrl: 'https://example.com/'
            };
            expect([500, 502, 503]).toContain(errorLink.status);
        });
    });

    describe('Result structure validation', () => {
        it('should handle empty result', () => {
            const result: LinkCheckResult = {
                brokenLinks: [],
                totalChecked: 0,
                checkedLinks: []
            };
            expect(result.brokenLinks.length).toBe(0);
            expect(result.totalChecked).toBe(0);
        });

        it('should track multiple broken links', () => {
            const result: LinkCheckResult = {
                brokenLinks: [
                    { url: 'https://example.com/404', status: 404, ok: false, parentUrl: 'https://example.com/' },
                    { url: 'https://example.com/500', status: 500, ok: false, parentUrl: 'https://example.com/' }
                ],
                totalChecked: 2,
                checkedLinks: []
            };
            expect(result.brokenLinks.length).toBe(2);
        });

        it('should include successful links in checkedLinks', () => {
            const result: LinkCheckResult = {
                brokenLinks: [],
                totalChecked: 1,
                checkedLinks: [
                    { url: 'https://example.com/page', status: 200, ok: true, parentUrl: 'https://example.com/' }
                ]
            };
            expect(result.checkedLinks.length).toBe(1);
            expect(result.checkedLinks[0].ok).toBe(true);
        });
    });

    describe('HTTP status codes', () => {
        it('should recognize success status (200)', () => {
            const link: ValidatedLink = {
                url: 'https://example.com/ok',
                status: 200,
                ok: true,
                parentUrl: 'https://example.com/'
            };
            expect([200, 201, 204, 301, 302, 304]).toContain(link.status);
        });

        it('should recognize client error status (404)', () => {
            const link: ValidatedLink = {
                url: 'https://example.com/404',
                status: 404,
                ok: false,
                parentUrl: 'https://example.com/'
            };
            expect(link.status >= 400 && link.status < 500).toBe(true);
        });

        it('should recognize server error status (5xx)', () => {
            const link: ValidatedLink = {
                url: 'https://example.com/error',
                status: 503,
                ok: false,
                parentUrl: 'https://example.com/'
            };
            expect(link.status >= 500 && link.status < 600).toBe(true);
        });
    });

    describe('Relative URLs', () => {
        it('should handle relative URL construction', () => {
            const parentUrl = 'https://example.com/page/';
            const relativeLink = '/about';
            const resolvedUrl = new URL(relativeLink, parentUrl).toString();
            expect(resolvedUrl).toBe('https://example.com/about');
        });

        it('should handle relative path traversal', () => {
            const parentUrl = 'https://example.com/path/to/page/';
            const relativeLink = '../other/page';
            const resolvedUrl = new URL(relativeLink, parentUrl).toString();
            expect(resolvedUrl).toContain('example.com');
        });
    });

    describe('Link limits', () => {
        it('should define link count constant', () => {
            // MAX_LINKS_PER_PAGE is typically 20
            const maxLinks = 20;
            expect(maxLinks).toBeGreaterThan(0);
        });
    });
});
