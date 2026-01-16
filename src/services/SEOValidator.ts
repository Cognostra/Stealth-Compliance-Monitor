/**
 * SEOValidator Service
 * 
 * Verifies that pages have correct Meta Tags for Social Sharing (Discord/Twitter/Facebook).
 * ensuring content looks good when shared.
 */

import { Page } from 'playwright';
import { logger } from '../utils/logger.js';

export interface SEOResult {
    url: string;
    valid: boolean;
    missingTags: string[];
    warnings: string[];
    imageStatus: 'ok' | 'missing' | 'broken' | 'unchecked';
    meta: {
        title?: string | null;
        description?: string | null;
        ogTitle?: string | null;
        ogDescription?: string | null;
        ogImage?: string | null;
        twitterCard?: string | null;
    };
}

export class SEOValidator {
    /**
     * Check SEO tags on the given page
     */
    async check(page: Page, url: string): Promise<SEOResult> {
        const result: SEOResult = {
            url,
            valid: true,
            missingTags: [],
            warnings: [],
            imageStatus: 'unchecked',
            meta: {}
        };

        try {
            // Extract meta tags from DOM
            const meta = await page.evaluate(() => {
                const getMeta = (name: string) =>
                    document.querySelector(`meta[name="${name}"]`)?.getAttribute('content') ||
                    document.querySelector(`meta[property="${name}"]`)?.getAttribute('content');

                return {
                    title: document.title,
                    description: getMeta('description'),
                    ogTitle: getMeta('og:title'),
                    ogDescription: getMeta('og:description'),
                    ogImage: getMeta('og:image'),
                    twitterCard: getMeta('twitter:card')
                };
            });

            result.meta = meta;

            // Validate presence
            if (!meta.title) result.missingTags.push('<title>');
            if (!meta.description) result.missingTags.push('meta[description]');
            if (!meta.ogTitle) result.missingTags.push('og:title');
            if (!meta.ogDescription) result.missingTags.push('og:description');
            if (!meta.ogImage) result.missingTags.push('og:image');
            if (!meta.twitterCard) result.missingTags.push('twitter:card');

            // Validate content length
            if (meta.ogDescription && meta.ogDescription.length < 10) {
                result.warnings.push(`og:description is too short (${meta.ogDescription.length} chars)`);
            }

            // Check og:image validity
            if (meta.ogImage) {
                try {
                    // Quick HEAD request to check image
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 3000);

                    const response = await fetch(meta.ogImage, {
                        method: 'HEAD',
                        signal: controller.signal
                    });

                    clearTimeout(timeout);

                    if (response.ok) {
                        result.imageStatus = 'ok';
                    } else {
                        result.imageStatus = 'broken';
                        result.warnings.push(`og:image is broken (Status: ${response.status})`);
                    }
                } catch (e) {
                    result.imageStatus = 'broken';
                    result.warnings.push(`og:image check failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
                }
            } else {
                result.imageStatus = 'missing';
            }

            if (result.missingTags.length > 0 || result.imageStatus === 'broken') {
                result.valid = false;
            }

            if (!result.valid) {
                logger.debug(`  seo defects on ${url}: ${result.missingTags.join(', ')}`);
            }

            return result;

        } catch (error) {
            logger.error(`SEO validation failed for ${url}: ${error}`);
            result.valid = false;
            result.warnings.push('Validation execution failed');
            return result;
        }
    }
}
