/**
 * AssetValidator Service
 * 
 * Verifies that assets (specifically images) on the page are loading correctly.
 * 
 * Detection Logic:
 * - Scans all <img> tags
 * - Checks naturalWidth > 0 (has pixels)
 * - Checks complete property (loaded)
 */

import { Page } from 'playwright';
import { logger } from '../utils/logger.js';

export interface AssetCheckResult {
    brokenImages: string[];
    totalImages: number;
}

export class AssetValidator {
    /**
     * Check for broken images on the given page
     */
    async check(page: Page): Promise<AssetCheckResult> {
        try {
            const result = await page.evaluate(() => {
                const images = Array.from(document.querySelectorAll('img'));
                const broken: string[] = [];

                images.forEach(img => {
                    // Check if image failed to load or has 0 width
                    if (!img.complete || img.naturalWidth === 0) {
                        const src = img.getAttribute('src') || '';
                        if (src) {
                            broken.push(src);
                        }
                    }
                });

                return {
                    brokenImages: broken,
                    totalImages: images.length
                };
            });

            if (result.brokenImages.length > 0) {
                logger.warn(`  🖼️ Found ${result.brokenImages.length} broken images`);
            }

            return result;
        } catch (error) {
            logger.error(`Asset validation failed: ${error}`);
            return { brokenImages: [], totalImages: 0 };
        }
    }
}
