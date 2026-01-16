/**
 * Social Media Meta Tags Checker
 * 
 * Validates Open Graph, Twitter Card, and other social media meta tags:
 * - Open Graph (Facebook, LinkedIn)
 * - Twitter Cards
 * - Schema.org structured data
 * - Apple/mobile meta tags
 * 
 * @author Community
 * @version 1.0.0
 * @tags seo, social, opengraph, twitter, meta
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../../src/core/CustomCheckLoader';

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[SocialMeta] Checking social media meta tags on: ${context.currentUrl}`);

    try {
        const metaData = await page.evaluate(() => {
            const getMeta = (selector: string) => {
                const el = document.querySelector(selector);
                return el?.getAttribute('content') || null;
            };

            return {
                // Open Graph
                ogTitle: getMeta('meta[property="og:title"]'),
                ogDescription: getMeta('meta[property="og:description"]'),
                ogImage: getMeta('meta[property="og:image"]'),
                ogUrl: getMeta('meta[property="og:url"]'),
                ogType: getMeta('meta[property="og:type"]'),
                ogSiteName: getMeta('meta[property="og:site_name"]'),
                ogLocale: getMeta('meta[property="og:locale"]'),

                // Twitter Card
                twitterCard: getMeta('meta[name="twitter:card"]'),
                twitterTitle: getMeta('meta[name="twitter:title"]'),
                twitterDescription: getMeta('meta[name="twitter:description"]'),
                twitterImage: getMeta('meta[name="twitter:image"]'),
                twitterSite: getMeta('meta[name="twitter:site"]'),
                twitterCreator: getMeta('meta[name="twitter:creator"]'),

                // Basic Meta
                title: document.title,
                description: getMeta('meta[name="description"]'),
                canonical: document.querySelector('link[rel="canonical"]')?.getAttribute('href'),

                // Mobile
                viewport: getMeta('meta[name="viewport"]'),
                themeColor: getMeta('meta[name="theme-color"]'),
                appleTouchIcon: document.querySelector('link[rel="apple-touch-icon"]')?.getAttribute('href'),

                // Schema.org
                hasSchemaOrg: !!document.querySelector('script[type="application/ld+json"]'),
            };
        });

        // =====================
        // Open Graph Checks
        // =====================

        if (!metaData.ogTitle) {
            violations.push({
                id: 'social-og-title-missing',
                title: 'Open Graph Title Missing',
                severity: 'medium',
                description: 'Missing og:title meta tag. This affects how your page appears when shared on Facebook, LinkedIn, etc.',
                remediation: 'Add <meta property="og:title" content="Your Page Title">',
                selector: 'head',
                url: context.currentUrl,
            });
        } else if (metaData.ogTitle.length > 60) {
            violations.push({
                id: 'social-og-title-too-long',
                title: 'Open Graph Title Too Long',
                severity: 'low',
                description: `og:title is ${metaData.ogTitle.length} characters. Recommended max is 60.`,
                remediation: 'Shorten og:title to prevent truncation in social shares.',
                selector: 'meta[property="og:title"]',
                url: context.currentUrl,
            });
        }

        if (!metaData.ogDescription) {
            violations.push({
                id: 'social-og-description-missing',
                title: 'Open Graph Description Missing',
                severity: 'medium',
                description: 'Missing og:description meta tag.',
                remediation: 'Add <meta property="og:description" content="Your page description">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        if (!metaData.ogImage) {
            violations.push({
                id: 'social-og-image-missing',
                title: 'Open Graph Image Missing',
                severity: 'high',
                description: 'Missing og:image. Social shares will have no preview image.',
                remediation: 'Add <meta property="og:image" content="https://example.com/image.jpg">. Recommended size: 1200x630 pixels.',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        if (!metaData.ogUrl) {
            violations.push({
                id: 'social-og-url-missing',
                title: 'Open Graph URL Missing',
                severity: 'low',
                description: 'Missing og:url meta tag.',
                remediation: 'Add <meta property="og:url" content="https://example.com/page">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        if (!metaData.ogType) {
            violations.push({
                id: 'social-og-type-missing',
                title: 'Open Graph Type Missing',
                severity: 'low',
                description: 'Missing og:type meta tag (e.g., website, article, product).',
                remediation: 'Add <meta property="og:type" content="website">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // =====================
        // Twitter Card Checks
        // =====================

        if (!metaData.twitterCard) {
            violations.push({
                id: 'social-twitter-card-missing',
                title: 'Twitter Card Missing',
                severity: 'medium',
                description: 'Missing twitter:card meta tag. Tweets linking to this page won\'t have rich previews.',
                remediation: 'Add <meta name="twitter:card" content="summary_large_image">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // Twitter falls back to OG, but explicit is better
        if (!metaData.twitterTitle && !metaData.ogTitle) {
            violations.push({
                id: 'social-twitter-title-missing',
                title: 'Twitter Title Missing',
                severity: 'low',
                description: 'No twitter:title and no og:title fallback.',
                remediation: 'Add twitter:title or og:title meta tag.',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        if (!metaData.twitterImage && !metaData.ogImage) {
            violations.push({
                id: 'social-twitter-image-missing',
                title: 'Twitter Image Missing',
                severity: 'medium',
                description: 'No twitter:image and no og:image fallback.',
                remediation: 'Add <meta name="twitter:image" content="..."> or <meta property="og:image" content="...">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // =====================
        // Schema.org Check
        // =====================

        if (!metaData.hasSchemaOrg) {
            violations.push({
                id: 'social-schema-missing',
                title: 'Schema.org Structured Data Missing',
                severity: 'low',
                description: 'No JSON-LD structured data found. This can improve search engine rich results.',
                remediation: 'Add <script type="application/ld+json"> with appropriate schema markup.',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // =====================
        // Canonical URL Check
        // =====================

        if (!metaData.canonical) {
            violations.push({
                id: 'social-canonical-missing',
                title: 'Canonical URL Missing',
                severity: 'medium',
                description: 'No canonical URL specified. This can cause duplicate content issues.',
                remediation: 'Add <link rel="canonical" href="https://example.com/page">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // =====================
        // Mobile Meta Check
        // =====================

        if (!metaData.themeColor) {
            violations.push({
                id: 'social-theme-color-missing',
                title: 'Theme Color Missing',
                severity: 'low',
                description: 'No theme-color meta tag for mobile browser UI customization.',
                remediation: 'Add <meta name="theme-color" content="#your-brand-color">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        if (!metaData.appleTouchIcon) {
            violations.push({
                id: 'social-apple-touch-icon-missing',
                title: 'Apple Touch Icon Missing',
                severity: 'low',
                description: 'No apple-touch-icon for iOS home screen bookmarks.',
                remediation: 'Add <link rel="apple-touch-icon" href="/apple-touch-icon.png">',
                selector: 'head',
                url: context.currentUrl,
            });
        }

        // Summary log
        const presentTags = Object.entries(metaData)
            .filter(([, v]) => v)
            .map(([k]) => k);
        context.logger.debug(`[SocialMeta] Found ${presentTags.length} social meta properties`);

    } catch (error) {
        context.logger.warn(`[SocialMeta] Check failed: ${error}`);
    }

    return violations;
}
