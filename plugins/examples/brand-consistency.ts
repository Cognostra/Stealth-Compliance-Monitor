/**
 * Brand Consistency Checker
 * 
 * Validates visual brand consistency across pages:
 * - Logo presence and correct dimensions
 * - Brand color usage
 * - Typography consistency
 * - Favicon presence
 * 
 * Configure via environment variables:
 *   BRAND_CHECK_LOGO_SELECTOR - CSS selector for logo element
 *   BRAND_CHECK_PRIMARY_COLOR - Expected primary brand color (hex)
 *   BRAND_CHECK_FONT_FAMILY - Expected primary font family
 * 
 * @author Community
 * @version 1.0.0
 * @tags branding, visual, consistency, ux
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../../src/core/CustomCheckLoader';

// Configuration (can be overridden via env vars)
const CONFIG = {
    logoSelector: process.env.BRAND_CHECK_LOGO_SELECTOR || 'img[alt*="logo"], .logo img, header img:first-of-type',
    primaryColor: process.env.BRAND_CHECK_PRIMARY_COLOR || null,
    fontFamily: process.env.BRAND_CHECK_FONT_FAMILY || null,
    minLogoWidth: parseInt(process.env.BRAND_CHECK_MIN_LOGO_WIDTH || '50'),
    maxLogoWidth: parseInt(process.env.BRAND_CHECK_MAX_LOGO_WIDTH || '400'),
};

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[Brand] Checking brand consistency on: ${context.currentUrl}`);

    try {
        // 1. Check for logo presence
        const logo = await page.$(CONFIG.logoSelector);
        if (!logo) {
            violations.push({
                id: 'brand-logo-missing',
                title: 'Logo Not Found',
                severity: 'medium',
                description: 'No logo element was found on the page.',
                remediation: `Add a logo image matching selector: ${CONFIG.logoSelector}`,
                url: context.currentUrl,
            });
        } else {
            // Check logo dimensions
            const box = await logo.boundingBox();
            if (box) {
                if (box.width < CONFIG.minLogoWidth) {
                    violations.push({
                        id: 'brand-logo-too-small',
                        title: 'Logo Too Small',
                        severity: 'low',
                        description: `Logo width (${Math.round(box.width)}px) is below minimum (${CONFIG.minLogoWidth}px).`,
                        remediation: 'Use a larger logo image for better visibility.',
                        selector: CONFIG.logoSelector,
                        url: context.currentUrl,
                    });
                }
                if (box.width > CONFIG.maxLogoWidth) {
                    violations.push({
                        id: 'brand-logo-too-large',
                        title: 'Logo Too Large',
                        severity: 'low',
                        description: `Logo width (${Math.round(box.width)}px) exceeds maximum (${CONFIG.maxLogoWidth}px).`,
                        remediation: 'Reduce logo size for better page layout.',
                        selector: CONFIG.logoSelector,
                        url: context.currentUrl,
                    });
                }
            }

            // Check if logo has alt text
            const altText = await logo.getAttribute('alt');
            if (!altText || altText.trim() === '') {
                violations.push({
                    id: 'brand-logo-no-alt',
                    title: 'Logo Missing Alt Text',
                    severity: 'medium',
                    description: 'Logo image is missing alt text for accessibility.',
                    remediation: 'Add descriptive alt text to the logo image (e.g., "Company Name Logo").',
                    selector: CONFIG.logoSelector,
                    url: context.currentUrl,
                });
            }
        }

        // 2. Check for favicon
        const favicon = await page.$('link[rel*="icon"]');
        if (!favicon) {
            violations.push({
                id: 'brand-favicon-missing',
                title: 'Favicon Not Found',
                severity: 'low',
                description: 'No favicon link was found. Favicons help with brand recognition in browser tabs.',
                remediation: 'Add a favicon: <link rel="icon" href="/favicon.ico">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // 3. Check primary color usage (if configured)
        if (CONFIG.primaryColor) {
            const colorUsage = await page.evaluate((expectedColor) => {
                const elements = document.querySelectorAll('*');
                let found = false;
                elements.forEach(el => {
                    const style = window.getComputedStyle(el);
                    const bgColor = style.backgroundColor;
                    const color = style.color;
                    const borderColor = style.borderColor;
                    
                    // Simple hex comparison (could be improved with color conversion)
                    if (bgColor.includes(expectedColor) || 
                        color.includes(expectedColor) ||
                        borderColor.includes(expectedColor)) {
                        found = true;
                    }
                });
                return found;
            }, CONFIG.primaryColor);

            if (!colorUsage) {
                violations.push({
                    id: 'brand-color-not-used',
                    title: 'Brand Color Not Detected',
                    severity: 'low',
                    description: `Primary brand color (${CONFIG.primaryColor}) was not found in use on the page.`,
                    remediation: 'Ensure consistent use of brand colors throughout the page.',
                    url: context.currentUrl,
                });
            }
        }

        // 4. Check typography consistency
        const fontStats = await page.evaluate(() => {
            const elements = document.querySelectorAll('body, h1, h2, h3, p, a, button');
            const fonts = new Map<string, number>();
            
            elements.forEach(el => {
                const style = window.getComputedStyle(el);
                const fontFamily = style.fontFamily.split(',')[0].trim().replace(/['"]/g, '');
                fonts.set(fontFamily, (fonts.get(fontFamily) || 0) + 1);
            });

            return Array.from(fonts.entries()).sort((a, b) => b[1] - a[1]);
        });

        // More than 4 different font families is usually too many
        if (fontStats.length > 4) {
            violations.push({
                id: 'brand-too-many-fonts',
                title: 'Too Many Font Families',
                severity: 'low',
                description: `${fontStats.length} different font families detected. Consider limiting to 2-3 for consistency.`,
                remediation: 'Standardize typography using a consistent font system.',
                evidence: `Fonts found: ${fontStats.slice(0, 5).map(([f]) => f).join(', ')}`,
                url: context.currentUrl,
            });
        }

        // 5. Check for Open Graph image (brand presence in social shares)
        const ogImage = await page.$('meta[property="og:image"]');
        if (!ogImage) {
            violations.push({
                id: 'brand-og-image-missing',
                title: 'Open Graph Image Missing',
                severity: 'low',
                description: 'No Open Graph image meta tag found. This affects brand presentation in social media shares.',
                remediation: 'Add <meta property="og:image" content="https://example.com/brand-image.png">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

    } catch (error) {
        context.logger.warn(`[Brand] Check failed: ${error}`);
    }

    return violations;
}
