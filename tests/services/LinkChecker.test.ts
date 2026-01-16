/**
 * Unit Tests for LinkChecker
 *
 * Tests link validation functionality including HEAD requests and caching.
 */

import { LinkChecker, ValidatedLink, LinkCheckResult } from '../../src/services/LinkChecker.js';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('LinkChecker', () => {
    let checker: LinkChecker;

    beforeEach(() => {
        checker = new LinkChecker();
        mockFetch.mockReset();
    });

    describe('checkLinks', () => {
        it('should detect broken links (404)', async () => {
            mockFetch.mockResolvedValue({ ok: false, status: 404 });

            const result = await checker.checkLinks(
                ['https://example.com/not-found'],
                'https://example.com'
            );

            expect(result.brokenLinks.length).toBe(1);
            expect(result.brokenLinks[0].status).toBe(404);
            expect(result.brokenLinks[0].url).toBe('https://example.com/not-found');
        });

        it('should detect server errors (500)', async () => {
            mockFetch.mockResolvedValue({ ok: false, status: 500 });

            const result = await checker.checkLinks(
                ['https://example.com/error'],
                'https://example.com'
            );

            expect(result.brokenLinks.length).toBe(1);
            expect(result.brokenLinks[0].status).toBe(500);
        });

        it('should NOT flag successful links (200)', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/working'],
                'https://example.com'
            );

            expect(result.brokenLinks.length).toBe(0);
        });

        it('should include totalChecked count', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/link1', 'https://example.com/link2'],
                'https://example.com'
            );

            expect(result.totalChecked).toBe(2);
        });

        it('should include checkedLinks array', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/link1'],
                'https://example.com'
            );

            expect(Array.isArray(result.checkedLinks)).toBe(true);
            expect(result.checkedLinks.length).toBe(1);
        });

        it('should track parentUrl for each link', async () => {
            mockFetch.mockResolvedValue({ ok: false, status: 404 });

            const result = await checker.checkLinks(
                ['https://example.com/broken'],
                'https://source-page.com'
            );

            expect(result.brokenLinks[0].parentUrl).toBe('https://source-page.com');
        });

        it('should handle network errors', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const result = await checker.checkLinks(
                ['https://unreachable.com'],
                'https://example.com'
            );

            expect(result.brokenLinks.length).toBe(1);
            expect(result.brokenLinks[0].error).toContain('Network error');
        });
    });

    describe('HEAD request method', () => {
        it('should use HEAD method for requests', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            await checker.checkLinks(
                ['https://example.com/link'],
                'https://example.com'
            );

            expect(mockFetch).toHaveBeenCalledWith(
                'https://example.com/link',
                expect.objectContaining({ method: 'HEAD' })
            );
        });
    });

    describe('caching', () => {
        it('should cache results for same URL', async () => {
            mockFetch.mockResolvedValue({ ok: false, status: 404 });

            // Check same URL twice with different parent pages
            await checker.checkLinks(['https://example.com/broken'], 'https://page1.com');
            await checker.checkLinks(['https://example.com/broken'], 'https://page2.com');

            // Should only fetch once due to caching
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it('should NOT cache different URLs', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            await checker.checkLinks(
                ['https://example.com/link1', 'https://example.com/link2'],
                'https://example.com'
            );

            expect(mockFetch).toHaveBeenCalledTimes(2);
        });
    });

    describe('batch checking', () => {
        it('should check multiple links', async () => {
            mockFetch.mockImplementation((url: string) => {
                if (url.includes('broken')) {
                    return Promise.resolve({ ok: false, status: 404 });
                }
                return Promise.resolve({ ok: true, status: 200 });
            });

            const links = [
                'https://example.com/working1',
                'https://example.com/broken1',
                'https://example.com/working2',
                'https://example.com/broken2'
            ];

            const result = await checker.checkLinks(links, 'https://example.com');

            expect(result.brokenLinks.length).toBe(2);
            expect(result.brokenLinks.every(r => r.url.includes('broken'))).toBe(true);
        });

        it('should deduplicate links before checking', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const links = [
                'https://example.com/same',
                'https://example.com/same',
                'https://example.com/same'
            ];

            await checker.checkLinks(links, 'https://example.com');

            // Should only check once (deduplicated)
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it('should limit links per page to MAX_LINKS_PER_PAGE', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            // Create 50 unique links
            const links = Array.from({ length: 50 }, (_, i) =>
                `https://example.com/link${i}`
            );

            const result = await checker.checkLinks(links, 'https://example.com');

            // Should only check up to 20 links (MAX_LINKS_PER_PAGE)
            expect(result.totalChecked).toBeLessThanOrEqual(20);
        });
    });

    describe('ValidatedLink result structure', () => {
        it('should include url field', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/test'],
                'https://example.com'
            );

            expect(result.checkedLinks[0].url).toBe('https://example.com/test');
        });

        it('should include status field', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/test'],
                'https://example.com'
            );

            expect(result.checkedLinks[0].status).toBe(200);
        });

        it('should include ok boolean', async () => {
            mockFetch.mockResolvedValue({ ok: true, status: 200 });

            const result = await checker.checkLinks(
                ['https://example.com/test'],
                'https://example.com'
            );

            expect(result.checkedLinks[0].ok).toBe(true);
        });
    });

    describe('timeout handling', () => {
        it('should handle timeout errors', async () => {
            mockFetch.mockRejectedValue(new Error('Timeout'));

            const result = await checker.checkLinks(
                ['https://slow-site.com'],
                'https://example.com'
            );

            expect(result.brokenLinks.length).toBe(1);
            expect(result.brokenLinks[0].error).toContain('Timeout');
        });
    });
});
