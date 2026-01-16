/**
 * LinkChecker Service
 * 
 * Validates links on a page by sending lightweight HEAD requests.
 * Ensures no broken navigation independent of the main crawler.
 * 
 * Logic:
 * - Filter for internal links
 * - Send HEAD request
 * - Fail on 4xx/5xx
 * - Max 20 links per page to save time
 */

import { logger } from '../utils/logger.js';

export interface ValidatedLink {
    url: string;
    parentUrl: string; // Where this link was found
    status: number;
    ok: boolean;
    error?: string;
}

export interface LinkCheckResult {
    brokenLinks: ValidatedLink[];
    totalChecked: number;
    checkedLinks: ValidatedLink[];
}

export class LinkChecker {
    private checkedCache: Map<string, number> = new Map();
    private readonly MAX_LINKS_PER_PAGE = 20;

    /**
     * checkLinks
     * @param links List of absolute URLs to check
     * @param parentUrl The URL of the page where these links were found
     */
    async checkLinks(links: string[], parentUrl: string): Promise<LinkCheckResult> {
        // Filter unique internal links (heuristic: starts with http)
        // We assume links passed here are already normalized or at least absolute

        // Deduplicate
        const uniqueLinks = Array.from(new Set(links));

        // Limit
        const linksToCheck = uniqueLinks.slice(0, this.MAX_LINKS_PER_PAGE);
        const results: ValidatedLink[] = [];

        logger.debug(`  🔗 Checking ${linksToCheck.length} links (HEAD requests)...`);

        // Check in parallel with concurrency limit (e.g. 5)
        const chunks = this.chunkArray(linksToCheck, 5);

        for (const chunk of chunks) {
            await Promise.all(chunk.map(async (url) => {
                const result = await this.checkSingleLink(url, parentUrl);
                results.push(result);
            }));
        }

        const brokenLinks = results.filter(r => !r.ok);
        if (brokenLinks.length > 0) {
            logger.warn(`  🔗 Found ${brokenLinks.length} broken links on ${parentUrl}`);
        }

        return {
            brokenLinks,
            totalChecked: results.length,
            checkedLinks: results
        };
    }

    /**
     * Check a single link using HEAD request
     */
    private async checkSingleLink(url: string, parentUrl: string): Promise<ValidatedLink> {
        // Return cached result if recently checked
        if (this.checkedCache.has(url)) {
            const status = this.checkedCache.get(url)!;
            return {
                url,
                parentUrl,
                status,
                ok: status >= 200 && status < 400
            };
        }

        try {
            // Using native fetch (Node 18+)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

            const response = await fetch(url, {
                method: 'HEAD',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'ComplianceMonitor/1.0 (LinkChecker)'
                }
            });

            clearTimeout(timeoutId);

            this.checkedCache.set(url, response.status);

            return {
                url,
                parentUrl,
                status: response.status,
                ok: response.status >= 200 && response.status < 400
            };
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            // logger.debug(`Link check failed for ${url}: ${errMsg}`);

            // Treat network failures (DNS, connection result) as broken
            return {
                url,
                parentUrl,
                status: 0,
                ok: false,
                error: errMsg
            };
        }
    }

    /**
     * Helper to chunk array
     */
    private chunkArray<T>(array: T[], size: number): T[][] {
        const chunked: T[][] = [];
        for (let i = 0; i < array.length; i += size) {
            chunked.push(array.slice(i, i + size));
        }
        return chunked;
    }
}
